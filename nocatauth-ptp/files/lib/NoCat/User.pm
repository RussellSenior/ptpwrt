package NoCat::User;

use NoCat;
use strict;
use vars qw( @REQUIRED @ISA );

@ISA	    = 'NoCat';
@REQUIRED   = qw( UserIDField UserPasswdField );

# new() instantiates a new NoCat::User object and returns it. 
# You'll probably want to use NoCat->user() to call this for you.
# Use ->set() and/or ->fetch() to actually populate the object returned.
#
sub new {
    my $class = shift;
    my $self = $class->SUPER::new( @_ );

    $self->{Data}   ||= {};
    return $self;
}

sub source {
    my $self = shift;
    $self->{Source} ||= $self->SUPER::source( @_ );
    return $self->{Source};
}

# set() takes a hash of values to set within the NoCat::User object.
# Cleartext passwords are automatically MD5 hashed.
#
sub set {
    my ( $self, %user ) = @_;
    for ( keys %user ) {
	$self->{Data}{$_} = $user{$_};
	$self->set_password( $user{$_} ) if $_ eq $self->{UserPasswdField};
    }
    return $self;   
}

# set_password() sets a new password, and notes the change so that
# the source driver can re-encrypt the password if need be. changed_password()
# allows the driver to detect this condition.
#
sub set_password {
    my ( $self, $new_pw, $encrypted ) = @_;
    $self->{Data}{$self->{UserPasswdField}} = $new_pw;
    $self->{Changed_Passwd} = not $encrypted;
    return $self->{Data};   
}

sub changed_password {
    my $self = shift;
    return $self->{Changed_Passwd};
}

# data() returns a hash containing the values of the User object. 
# Don't modify this hash, please.
#
sub data {
    my $self = shift;
    return $self->{Data};
}

# id() returns the unique user ID from the User object.
#
sub id {
    my $self = shift;
    $self->{Data}{ $self->{UserIDField} } = shift if @_;
    return $self->{Data}{ $self->{UserIDField} };
}

# passwd() returns the (hopefully hashed) password from the User object.
#
sub passwd {
    my $self = shift;
    $self->set_password( @_ ) if @_;
    return $self->{Data}{ $self->{UserPasswdField} };
}

# create() stores a new NoCat::User object after it's been populated.
#
sub create {
    my $self = shift;
    $self->source->create_user( $self );
    return $self;
}

# fetch() retrieves an existing NoCat::User object from the database.
# fetch() takes a hash containing field/value pairs to match against existing objects, and
#    returns the first one it finds.
#
#    $user->fetch( $user->{UserIDField} => "Foo" ); 
#      ... is probably the logical way to fetch a user uniquely identified as "Foo".
#
sub fetch {
    my ( $self, $id )    = @_;
    $self->{Data} = $self->source->fetch_user_by_id( $id );
    return $self;
}

sub store {
    my ( $self, $id )    = @_;
    $self->source->store_user( $self );
    return $self;
}

# authenticate() takes a cleartext password and returns true if the User object's
#    password matches the existing hashed password.
#
sub authenticate {
    my ( $self, $user_pw )  = @_;
    return $self->source->authenticate_user( $user_pw,$self );
}

sub groups {
    my ( $self ) = @_;

    $self->{Group} = $self->source->fetch_groups_by_user( $self ) || {}
	unless $self->{Group};

    return( wantarray ? keys %{$self->{Group}} : $self->{Group} );
}

1;
