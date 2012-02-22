package NoCat::Source;

use NoCat qw( ANY );
use strict;
use vars qw( @ISA @REQUIRED );

@ISA	    = 'NoCat';
@REQUIRED   = qw( DataSource );

my @API_Methods = qw(
    create_user
    store_user
    authenticate_user		     

    fetch_users_by_group

    add_group_member
    drop_group_member
    update_group_member
);

sub _virtual {
    my ($self, $func) = @_;

    require Carp;
    Carp::croak( ref($self), " does not implement a $func method" );
}

for my $method ( @API_Methods ) {
    no strict 'refs';
    *{__PACKAGE__ . "::$method"} = sub { _virtual($_[0], $method) };
}

# These are really dummy functions... if a user shows up, we'll call them
# a member of the magical ANY group for now. With these two functions,
# a Source driver can get away with implementing authenticate_user at
# a bare minimum.
#
sub fetch_user_by_id {
    my ( $self, $id )    = @_;    
    return { $self->{UserIDField} => $id };
}

sub fetch_groups_by_user {
    my ( $self, $user ) = @_;
    return { ANY => 0 };
}


# The one non-dummy function.
#
sub new {
    my $self	= shift;
    my $class	= ref( $self ) || $self;

    if ( $class eq __PACKAGE__ ) {
	# We've been called as NoCat::Source->new, which means we need to
	# load nocat.conf and figure out which data source plugin we're 
	# supposed to use.
	return $self->instantiate( DataSource => @_ );
    } else {
	# We've been called as NoCat::Source::Foo->new, so pass arguments
	# to NoCat->new and return.
	return $self->SUPER::new( @_ );
    }
}

1;
