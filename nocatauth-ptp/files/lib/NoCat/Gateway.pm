package NoCat::Gateway;

use IO::Socket;
use IO::Select;
use IO::Pipe;
use NoCat qw( PERMIT DENY PUBLIC MEMBER OWNER LOGIN ANY );
use vars qw( @ISA @REQUIRED @EXPORT_OK *FILE );
use strict;

require 5.004; # for IO::Select/Pipe

@ISA	    = 'NoCat';
@EXPORT_OK  = @NoCat::EXPORT_OK;
@REQUIRED   = qw( GatewayMode GatewayPort ListenQueue PollInterval LoginTimeout );

sub new {
    my $self	= shift;
    my $class	= ref( $self ) || $self;

    # We've been called as NoCat::Gateway->new, which means we need to
    # load nocat.conf and figure out which gateway plugin we're 
    # supposed to use.
    #
    return $self->instantiate( GatewayMode => @_ )
	if $class eq __PACKAGE__;
    
    # We've been called as NoCat::Source::Foo->new, so pass arguments
    # to NoCat->new and get the new object.
    #
    $self = $class->SUPER::new( @_ );

    $self->{Peer} ||= {};
    return $self;
}

sub bind_socket {
    my $self = shift;
    my @address;

    return $self->{ListenSocket} if $self->{ListenSocket};

    # If no IP address is specified, try them all.
    if ( $self->{GatewayAddr} ) {
	@address = ( LocalAddr => $self->{GatewayAddr} );
    } else {
	@address = ( MultiHomed => 1 );
    }

    # Use a specified port if there is one.
    push @address, ( LocalPort => $self->{GatewayPort} ) 
	if $self->{GatewayPort};

    my $server = IO::Socket::INET->new(
	Listen	    => $self->{ListenQueue},
	Proto	    => "tcp",
	Reuse	    => 1,
	@address
    );

    $self->log( 0, "Can't bind to port $self->{GatewayPort}: $!.",
	"(Is another gateway already running?)" )
	unless $server;

    $self->log( 8, "Binding listener socket to ", $server->sockhost );

    return( $self->{ListenSocket} = $server );
}

sub open_log {
    my $self = shift;
    my $log  = $self->{GatewayLog};

    # Do nothing if we're using syslog (it's handled in NoCat.pm)
    return unless $log and $self->{LogFacility} ne "syslog";

    open STDERR, ">>$log" or die "Can't open log file $log: $!";
    open STDOUT, ">&STDERR" or die "Can't dup STDOUT to STDERR: $!";
}

sub pool {
    my $self = shift;
    $self->{SocketPool} ||= IO::Select->new( $self->bind_socket );
    return $self->{SocketPool};
}

sub clear_pool {
    my $self = shift;
    delete $self->{SocketPool};
}

sub run {
    my $self	= shift;
    my $hup = 0;
    
    return unless $self->bind_socket;

    local $SIG{PIPE} = "IGNORE"; 
    local $SIG{CHLD} = "IGNORE";
    local $SIG{HUP} = sub { $hup++ };

    # Reset history.
    $self->{GatewayStartTime}	= scalar localtime;
    $self->{LastConnectionTime}	= "none";
    $self->{TotalConnections}	= 0;

    # Setup for inactive sessions checking
    my $inactive = time + $self->{IdleTimeout}; # Only check every 5 minutes
    my $expired  = time + 10; # Check no more often than every 10s

    # Handle connections as they come in.
    #
    while ( 1 ) {
	# Spend some time waiting for something to happen.
	# If poll_socket doesn't return true, we're a child who's done.
	#
	$self->poll_socket or return;

	# See if any logins have reached their timeout period.
	if (time > $expired) {
	    $self->check_expired;
	    $expired += 10;
	}

        # See if any sessions have been inactive too long
        if ( $self->{MaxMissedARP} and time >= $inactive ) {
            $self->check_inactive;
            $inactive += $self->{IdleTimeout}; 
        }

        # Have we caught a HUP?  If so, re-initialize log files.
        if ( $hup ) {
            $self->open_log;
            $self->log( 6, "HUP received, resetting log file." );
            $hup = 0;
        }
    } # loop forever
}

sub poll_socket {
    my $self	= shift;
    my $server	= $self->bind_socket;
    my @ready   = $self->pool->can_read( $self->{PollInterval} );

    if (@ready and not defined $ready[0]) {
	$self->log( 1, "poll_socket: $!" );
	return 1;
    }

    for my $listen (@ready) {
	# $self->log( 10, "Ready in poll_socket: @ready" );

	# If the inet socket is ready for reading, spawn a child.
	my $is_parent;

	if ( $listen eq $server ) {
	    # Get the client socket to pass to the child.
	    my $client = $server->accept;

	    # Don't spawn a child process if ForkOff is false.
	    $is_parent = $self->spawn_child if $self->{ForkOff};

	    unless ($is_parent) {
		# We're the child (or we didn't fork), so process
		# the client's request.
		$self->accept_client( $client );
		
		# Exit iff we actually succeeded in forking.
		return 0 if defined $is_parent; 
	    }
	} else {
	    # Otherwise, this is a child reporting back via a pipe.
	    $self->accept_child( $listen );
	}
    }

    return 1;
}

sub parent {
    my ($self, $pipe) = @_;
    $self->{ParentPipe} = $pipe if $pipe;
    return $self->{ParentPipe};
}

sub notify_parent {
    my ($self, $action, $peer) = @_;
    if (my $parent = $self->parent) {
	my %args = %$peer; 

	# Don't pass any references back to the parent, they
	# wouldn't know what to do with it anyway.
	my @refs = grep( ref($args{$_}), keys %args );
	delete @args{@refs};

	# Notify the parent any special action we're taking about this peer.
	$args{Action} = $action if defined $action;	

	$self->log( 10, "Notifying parent of $action on peer", $peer->id );

	# Reformat the peer's basic info and send it to the parent process.
	print $parent $self->deparse( %args )
	    or $self->log( 1, "Can't notify parent of $action: $!" );
    }
}

sub spawn_child {
    my $self = shift;
    my $pipe = IO::Pipe->new;
    my $pid;

    if ($pid = fork) {
	# We're the parent. Poll for writes from the kid.
	$self->log( 10, "Spawning child process $pid." );
	$self->pool->add( $pipe->reader );

    } elsif (defined $pid) {
	# We're the kid. Get ready to write back to the parent.
	$self->parent( $pipe->writer );

	# Close any open listener sockets.
	$self->clear_pool;

    } else {
	$self->log( 1, "spawn_child failure: $!" );
    }
    
    return $pid;
}

sub accept_child {
    my ($self, $listen) = @_;
    my $r = read( $listen, my $msg, 500_000 ); # arbitrary limit
    if ($r) {
	# The child process has news about a peer.
	# Parse that info and store it.
	my $peer    = $self->peer( $self->parse($msg) );
	my $action  = delete( $peer->{Action} ) || "";

	$self->log( 10, "Got notification $action of peer", $peer->id );    

	if ( $action eq DENY ) {
	    $self->remove_peer( $peer );
	} else {
	    $self->add_peer( $peer );
	}
	if ( $action eq PERMIT ) {
	    # Increment this only once per connection.
	    $self->{TotalConnections}++;
        
	    # Note the connection time.
	    $self->{LastConnectionTime} = scalar localtime;
	}
    } elsif (not defined $r) {
	$self->log( 2, "Can't read from child pipe: $!" );
    }

    # if $r returned false, but not undef, then the child quit 
    # normally, but with nothing to say?

    $self->pool->remove( $listen );

    my $result = $listen->close;
    $self->log( 10, "Child process returned $result" ) if $r;
}

sub accept_client {
    my ($self, $sock)	= @_;
    my $peer	    = $self->peer( $sock );
    my $peerhost    = $sock->peerhost;    

    $self->log( 8, "Connection to " . $sock->sockhost . " from $peerhost" );

    # Set the UNIX alarm clock.
    alarm( $self->{HandleTimeout} ) if $self->{HandleTimeout};

    # Wrap the call to handle() in eval{}, so we catch the
    # exception when the alarm goes off.
    #
    # Then turn the alarm off, Schuyler, you moron!
    eval { 
	$self->handle( $peer );
	alarm 0 if $self->{HandleTimeout};
    };

    # Note the warning if the call to handle() threw an exception.
    $self->log( 1, "$peerhost: $@" ) if $@;
}

sub check_expired { 
    my $self = shift;
    while ( my ($token, $peer) = each %{$self->{Peer}} ) {
	if ( $peer->expired ) {
	    $self->log( 8, "Expiring connection from", $peer->ip, $peer->mac, "." );
	    $self->deny( $peer );
	}
    }
}

# check_inactive uses the ARP table to determine when a session has gone inactive
# It assumes that the MAC addresses disappears from the table before the IP address
# and that that indicates inactivity.  They are typically given one grace miss.

sub check_inactive { 
    my $self = shift;

    # Bag if we're not paying attention to MAC addresses.
    return if $self->{IgnoreMAC};

    # Only fetch the table once to save some ticks
    my $arp = $self->firewall->arp_table( $self->firewall->BY_MAC );
    $self->log( 8, "DEBUG arp: ", $arp, "." );
    
    while ( my ($token, $peer) = each %{$self->{Peer}} ) {
        if ( defined $arp->{$peer->mac} ) {
            $peer->{MissedARP} = 0;
        } else {
	    # How many missed ARPs should it take?
	    if ( ++$peer->{MissedARP} >= $self->{MaxMissedARP} ) { 
	        $self->log( 8, "Expiring inactive connection from", $peer->ip, "." );
	        $self->deny( $peer );
            }
	}
    }
}

sub read_http_request {
    my ( $self, $peer ) = @_;
    my $socket = $peer->socket;    

    # Get the HTTP header intro line.
    my $line = <$socket>;
    return $self->log( 6, "No header line from " . $peer->ip ) 
	if not $line or $line =~ /^\s*$/os;

    my ( $method, $uri ) = split /\s+/, $line;
    my %head;

    # Read the HTTP header fields.
    while (defined( $line = <$socket> )) {
	$line =~ s/^\s+|\s+$|User-//gos;
	last unless length $line;
	#my ( $key, $val ) = split /:\s+/, $line, 2;
	my ( $key, $val ) = split /:\s+/, $line, 2;
        #$val =~ split /User-/, $val;
        $head{ ucfirst lc $key } = $val;
    }

    $head{Method}     = $method || "GET";
    $head{URI}	      = $uri || "/";
    $head{URL}	      = ($head{Host} ? "http://$head{Host}$head{URI}" : $self->{HomePage}) || "";
    #$head{UserAgent}  = ($head{UserAgent}) || "null";

    return \%head;
}

sub handle {
    die "NoCat::Gateway cannot handle connections on its own.";
}

sub add_peer {
    my ($self, $peer) = @_;
    $self->{Peer}{$peer->id} = $peer;
}

sub remove_peer {
    my ($self, $peer) = @_;
    return delete $self->{Peer}{$peer->id};
}

sub permit {
    my ( $self, $peer, $class ) = @_;
    my $fw = $self->firewall( GatewayAddr => $peer->gateway_ip );
    my $action;

    # Stash the peer object for future use.
    #
    $self->add_peer( $peer );

    # Update its expiration timestamp.
    #
    $peer->timestamp(1);

    # Get *our* notion of what the peer's service class should be.
    #
    $class = $self->classify( $peer, $class );

    my $prior_class = $peer->status;

    if ( $prior_class ne $class ) {
	# Insert the rule for the new class of service...
	#
	$fw->permit( $class, $peer->mac, $peer->ip );
	
	# *BEFORE* removing the rule for the *old* class of service, if any.
	# This way we don't drop packets for stateful connections in the 
	# event of service upgrade.
	#
	if ( $prior_class and $prior_class ne DENY ) {
	    $self->log( 5, "Upgrading ", $peer->user, 
		" from $prior_class to $class service." );

	    $fw->deny( $prior_class, $peer->mac, $peer->ip );
	    $action = "Upgrade";
	} else {
	    $self->log( 5, "User", ( $peer->user || $peer->ip ), $peer->mac, "permitted in class $class" );
	    $action = PERMIT;
	}

	$peer->status( $class );
    } else {
	$self->log( 5, "User", $peer->user, " renewed in class $class" );
	$action = "Renew";
    }

    # Tell the parent process about it.
    $self->notify_parent( $action => $peer );
}

sub deny {
    my ( $self, $peer ) = @_;
    my $mac	= $peer->mac;

    # if we don't know the peer's MAC address, it must have been
    # an incidental connection (e.g. notification) that can be ignored.
    return unless $mac or $self->{IgnoreMAC};

    $peer = $self->remove_peer( $peer )
	or return $self->log( 4, "Denying unknown MAC address $mac?" );

    my $class	= $peer->status;

    return $self->log( 7, "Denying peer $mac without prior permit." )
	if not $class or $class eq DENY;

    $self->log( 5, "User", ( $peer->user || $peer->ip ),
	$peer->mac, "denied service. Connected since" ,
	scalar localtime $peer->connect_time, "." ); 

    my $fw = $self->firewall( GatewayAddr => $peer->gateway_ip );
    $fw->deny( $class, $mac, $peer->ip ); 

    $peer->status( DENY );

    # Tell the parent process about it.
    $self->notify_parent( DENY, $peer );
}

sub classify {
    my ( $self, $peer ) = @_;
    my $user = $peer->user;
    my $class;
    
    if ($user and grep( $user eq $_, $self->owners )) {
    	$class = OWNER;
    } else {
	$self->log(9, "User (@{[ $peer->groups ]}) v. trusted (@{[ $self->groups ]})" );
        my %prospect = map { $_ => 1 } $self->groups;
	if ( grep $_, @prospect{ $peer->groups } ) {
	    $class = MEMBER;
	} else {
	    $class = PUBLIC;
	}
    }

    return $peer->class( $class );
}

sub owners {
    my $self = shift;
    my @owners;
    
    return @{$self->{_OwnerList}} if $self->{_OwnerList};    

    # Owners directive.
    push @owners,  grep($_, split( /\s+/, $self->{Owners} )) if $self->{Owners};

    # Or perhaps listed per line in an OwnersFile.
    if ( $self->{OwnerFile} ) {
	open( FILE, "<$self->{OwnerFile}" ) 
	    or return $self->log( 1, "OwnerFile $self->{OwnerFile}: $!" );

	while ( <FILE> ) {
	    # Throw away leading/trailing space.
	    s/^\s+|\s+$//gios;
	    # Owner must start with an alphanumeric.
	    push @owners, $_ if /^\w+/o;
	}
	close FILE;
    }

    # This cache doesn't get reset, which means you have to restart the server 
    # if the list changes.
    $self->{_OwnerList} = \@owners;
    return @owners;
}

sub groups {
    my $self = shift;
    
    # TrustedGroups can be a space- or comma-separated list 
    # of trusted cooperatives. TrustedGroups can be set the magical "Any"
    # group, and will default to this if unset.

    if ( my $group = $self->{TrustedGroups} ) {
	return grep($_, split( /\W+/, $group ));
    } else {
	return ANY;
    }
}

sub redirect {
    my ( $self, $peer, $url ) = @_;

    $peer->socket->print(
	"HTTP/1.1 302 Moved\r\n",
	"Location: $url\r\n\r\n", qq{
<html>
<body bgcolor="white" text="black">
You should be redirected now.  If not, click <a href="$url">here.</a>
</body>
</html>
});

    $peer->socket->close;
}

sub peer_count {
    my $self = shift;
    scalar keys %{$self->{Peer}};
}

sub status {
    my ( $self, $peer, $url ) = @_;
    my ( $FormatOn, $FormatOff, $ConnectedMin, $MinLeft, $Mac, $MacSearch );
    my $user_table = qq{<tr><th>User</th><th>Connected Since</th><th>Connected
	Minutes</th><th>Minutes left</th><th>MAC Address</th></tr>\n};

    for my $u (values %{$self->{Peer}}) {
        if ( $u->ip eq $peer->socket->peerhost ) {
            $FormatOn = "<b>";
            $FormatOff = "</b>";
        } else {
            $FormatOn = "";
            $FormatOff = "";
        }
	my $id = ($self->{GatewayMode} eq "Open" ? $u->ip : $u->user);
        $ConnectedMin = time() - $u->connect_time;
        $MinLeft = int (( $self->{LoginTimeout} - $ConnectedMin ) / 60);
        $ConnectedMin = int ( $ConnectedMin / 60 );
        substr($Mac,9,5) = "XX:XX" if $Mac = $u->mac;
	    # Mask the MAC for the saftey of the guilty
        $MacSearch = substr($Mac,0,2) . substr($Mac,3,2) . substr($Mac,6,2);
	$user_table .= qq{<tr><td>$FormatOn$id$FormatOff</td>}
            . qq{<td>$FormatOn} . localtime($u->connect_time) . qq{$FormatOff</td>}
	    . qq{<td align="center">$FormatOn$ConnectedMin$FormatOff</td>}
            . qq{<td align="center">$FormatOn$MinLeft$FormatOff</td>}
	    . qq{<td align="center">$FormatOn<a 
href="http://standards.ieee.org/cgi-bin/ouisearch?$MacSearch">$Mac</a>$FormatOff</td></tr>\n};
    }

    $self->log( 8, "Serving status page ", $peer->socket->peerhost );

    $self->respond( $peer, StatusForm => {
	GatewayAddr	 => $peer->gateway_ip,
	LocalTime	 => scalar localtime,
	ConnectionCount	 => $self->peer_count,
	UserTable	 => $user_table } 
    );
}

sub respond {
    my ($self, $peer, $template, $extra) = @_;
    $peer->socket->print(
	"HTTP/1.1 200 OK\r\n",
	"Content-type: text/html\r\n\r\n",
	$self->template( $template => $extra )
    );
    $peer->socket->close;
}

sub no_response {
    my ( $self, $peer ) = @_;
    $peer->socket->print(
	"HTTP/1.1 204 No Reponse\r\n\r\n" );
    $peer->socket->close;
}

1;
