package NoCat::Group;

use NoCat;
use strict;
use vars qw( @REQUIRED @ISA );

@ISA	    = 'NoCat';

sub new {
    my $class = shift;
    my $self  = $class->SUPER::new( @_ );

    $self->{Users}  ||= {};
    $self->{Former} ||= {};
    
    return $self;
}

sub source {
    my $self = shift;
    $self->{Source} ||= $self->SUPER::source( @_ );
    return $self->{Source};
}

sub id {
    my $self = shift;
    $self->{Name} = shift if @_;
    return $self->{Name};
}

sub users {
    my $self = shift;
    return $self->{Users};
}

sub create {
    my ( $self, $id ) = @_;
    $self->id( $id ) if $id;
    return $self;
}

sub fetch {
    my ( $self, $id ) = @_;
    $self->id( $id ) if $id;

    my $users = $self->source->fetch_users_by_group( $self );
    if ( $users ) {
	%{$self->{Former}} = %{$self->{Users}} = %$users;
    } else {
	$self->id( undef );
    }
    return $self;
}

sub store {
    my $self	= shift;
    my $member	= $self->{Users};
    my $former	= $self->{Former};

    while ( my ($user, $status) = each %$member ) {
	if ( exists $former->{$user} ) {
	    if (  $former->{$user} ne $status ) {
		$self->source->update_group_member( $self, $user, $status );
		$former->{$user} = $status;
	    }
	} else {
	    $self->source->add_group_member( $self, $user, $status );
	}
    }

    while ( my ($user, $status) = each %$former ) {
	$self->source->drop_group_member( $self, $user )
	    unless exists $member->{$user};
    }
    
    %$former = %$member;
    return scalar keys %$member;
}

sub add {
    my ( $self, $user, $admin ) = @_;
    $self->{Users}{$user->id} = $admin || 0;
    return $self;
}

sub drop {
    my ( $self, $user ) = @_;
    delete $self->{Users}{$user->id};
    return $self;
}

sub admin {
    my ( $self, $user, $admin ) = @_;
    $self->{Users}{$user->id} = $admin if defined $admin;
    return $self->{Users}{$user->id};
}

1;
