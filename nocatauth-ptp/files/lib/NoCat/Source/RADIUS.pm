package NoCat::Source::RADIUS;

use NoCat::Source;
use Authen::Radius;
use strict;
use vars qw( @ISA @REQUIRED );

@ISA	    = qw( NoCat::Source );
@REQUIRED   = qw( 
    RADIUS_Host RADIUS_Secret UserIDField 
);

sub radius {
    my ($self) = @_;

    unless ($self->{Radius}) {
	my $r;
	my $Hosts = $self->{RadiusHostsToUse};

	if(! defined($Hosts)) {  #This is really the first time through and I need to generate my list of servers
	    $self->{RADIUS_Host} =~ s/,,/,/g;  #just to eliminate any blank entries
	    my(@Hosts) = split(/,/,$self->{RADIUS_Host});
	    if($self->{RADIUS_Order} && $self->{RADIUS_Order}) {  #mix em up.
		my @TmpHosts;
		my %UsedHosts;
		for(my $i=0;$i <= $#Hosts; $i++) {
		    my $TmpHost;
		    while(! $TmpHost || ($TmpHost && $UsedHosts{$TmpHost})) {
			$TmpHost = $Hosts[int(rand($#Hosts + 1))];
			last if ! $UsedHosts{$TmpHost};
		    }	
		    $UsedHosts{$TmpHost} = 1;
		    $TmpHosts[$i] = $TmpHost;
		}
		@Hosts = @TmpHosts;
	    }
	     $self->{RadiusHostsToUse} = \@Hosts;  #List generated.
	} 

	if($self->{RadiusHostsToUse}) {   #go through servers one by one
	    foreach my $Host (@{$self->{RadiusHostsToUse}}) {
		my $Secret = $self->{RADIUS_Secret} ? $self->{RADIUS_Secret} : "";
		if($Host =~ s/\*(.*)$//) {
		    $Secret = $1;
		}
		$self->log( 0, "Connecting to RADIUS server $Host with Timeout " . $self->{RADIUS_TimeOut} );
		$r  = Authen::Radius->new(  
					    Host	=> $Host,
					    Secret	=> $Secret,
					    Timeout => $self->{RADIUS_TimeOut}
					    );
		last if $r;   #If we have a good connection, we're done
		$self->log( 0, "Failed to connect to RADIUS server $Host" );
	    }
	    if ($r) {  # This is almost always the case...
		$self->{Radius} = $r;
	    } else {
		$self->log( 0, "Can't connect to RADIUS server(s) $self->{RADIUS_Host}" );
	    }
	} else {
	    return undef;  #no host for them!
	}
    }

    return $self->{Radius};
}

sub usenextserver {  #If I fail, take the most recent host out and 
    my $self = shift;
    return unless $self->{RadiusHostsToUse};   #unless I've been through the radius sub above, forget it
    my @Hosts = @{$self->{RadiusHostsToUse}};
    my $popped = shift(@Hosts);  #say goodbye to the first one
    $self->log(0, "popped $popped in usenextserver");
    undef($self->{Radius});  #so radius above will get a new one.
    $self->{RadiusHostsToUse} = \@Hosts;
}

sub authenticate_user {
    my ($self, $user_pw, $user) = @_;

    my $result;
    my $loop = 0;
    while(! $loop) {
	my $radius = $self->radius;
	# mimic the check_pwd from Authen::Radius
	$radius->clear_attributes;
	$radius->add_attributes (
				 { Name => 1, Value => $user->id },
				 { Name => 2, Value => $user_pw }
	);

	my $radiuscheckok = 0;
	if($radius->send_packet (Authen::Radius::ACCESS_REQUEST())) {
	    my $radiusresult = $radius->recv_packet;
	    if(defined($radiusresult)) {
		$radiuscheckok = 1;
		$result = 1 if $radiusresult == Authen::Radius::ACCESS_ACCEPT();
		if($radiusresult == 2) {
		    $result = 1;
		} else {
		    if($radiusresult == Authen::Radius::ACCESS_REJECT()) {
			$self->log(0,"User rejected!");
		    } else {
			$self->log(0,"Radius failure: unknown cause");
		    }
		}
	    }
	}

	if(! $radiuscheckok) {
	    my(@TmpHosts) = @{$self->{RadiusHostsToUse}};
	    if(! $#TmpHosts) {  #it failed because we've run out of servers
		$loop = 1;
		$result = 0;
		$self->log(0,"Out of servers to try");
	    } else {
		$self->log(0,"Going to the next server: check the secret/port/reachability of this one");
		$self->usenextserver;
	    }
	} else {
	    $loop = 1;
	}
    }
    return $result;
}



1;
