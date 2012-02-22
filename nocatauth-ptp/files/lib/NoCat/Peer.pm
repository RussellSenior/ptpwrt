package NoCat::Peer;

use NoCat qw( PUBLIC ANY );
use vars qw( @ISA @REQUIRED );
use strict;

@REQUIRED   = qw( LoginTimeout );
@ISA	    = 'NoCat';

sub new {
    my $class = shift;
    my $self = $class->SUPER::new( @_ );
    
    $self->socket( $self->{Socket} ) if defined $self->{Socket};
    $self->class( "", "" ) unless defined $self->{Class};
    $self->groups( $self->{Groups} || "" ) unless ref $self->{Groups};
    $self->timestamp;
    return $self;
}

sub socket {
    my ( $self, $sock ) = @_;
    if ( defined $sock ) {
	$self->{Socket} = $sock;
	$self->gateway_ip( $sock->sockhost );
	$self->ip( $sock );  # Seed IP address.
    }
    return $self->{Socket};
}

sub gateway_ip {
    my ( $self, $addr ) = @_;
    $self->{GatewayAddr} = $addr if defined $addr;
    return $self->{GatewayAddr};
}

sub ip {
    my ( $self, $sock ) = @_;

    if ( $sock or not defined $self->{IP} ) {
	my $old_ip = $self->{IP};

	if ( $sock ||= $self->socket ) {
	    $self->{IP} = $sock->peerhost;
	} elsif ( my $mac = $self->{MAC} ) {
	    $self->{IP} = $self->firewall->fetch_ip( $mac );
	}
    
	# If this peer is coming from a different IP, forget their previous status.
	$self->status("") if $old_ip and $old_ip ne $self->{IP};
    }

    return $self->{IP};
}

sub mac {
    my ( $self, $mac ) = @_;

    return "" if $self->{IgnoreMAC};

    $self->{MAC} = $mac if defined $mac;
    $self->{MAC} = $self->firewall->fetch_mac( $self->{IP} )
	if $self->{IP} and not defined $self->{MAC};

    return $self->{MAC};
}

sub id {
    my $self = shift;
    return $self->mac unless $self->{IgnoreMAC};
    return $self->ip;
}

sub connect_time {
    my $self = shift;
    $self->{ConnectTime} ||= time;
    return $self->{ConnectTime};
}

sub timestamp {
    my ( $self, $reset ) = @_;
    $self->connect_time; # Seed ConnectTime...
    $self->{Timestamp} = time + $self->{LoginTimeout} 
	if defined $reset or not defined $self->{Timestamp};
    return $self->{Timestamp};
}

sub expired {
    my $self = shift;
    if ( $self->{MaxPingMisses} ) {
        return ($self->heartbeat > $self->{MaxPingMisses}) 
    } else {
	return ($self->timestamp < time)
    }
}

sub heartbeat {
    my ( $self, $alive ) = @_;

    # $self->{Pulse} = 0 unless defined $alive;

    if ( $alive and $self->{Pulse} > 0 ) {
	$self->{Pulse}--;
    } elsif ( defined $alive and not $alive ) {
	$self->{Pulse}++;
    }

    return $self->{Pulse};
}

sub token {
    my ( $self, $reset ) = @_;
    my $token = $self->{Token};
    my $salt;

    if ( defined $reset or not defined $token ) {
	$token = int rand 0xFFFFFFFF unless $token;
	$self->{Token} = $self->increment_token( $token );
    }

    return $self->{Token};
}

sub user {
    my ( $self, $user ) = @_;
    # $self->log( 9, "Peer::user called: $self=[$self->{User}] (@_)" );
    $self->{User} = $user if defined $user;
    return $self->{User};
}

sub status {
    my ( $self, $status ) = @_;
    $self->{Status} = $status if defined $status;
    return( $self->{Status} || "" );
}

sub class {
    my ( $self, $class, $user ) = @_;
    $self->{Class} = $class if defined $class;
    $self->user( $user ) if defined $user;
    return( $self->{Class} || PUBLIC );
}

sub groups {
    my ( $self, $groups ) = @_;
    
    # Every user who is a member of *some* group is automatically a 
    # member of the magical "Any" group.
    #
    my $list = $self->{Groups} ||= [];
    @$list = grep $_, split( /\W+/, $groups ), ANY
	if $groups;

    return @$list;
}

1;
