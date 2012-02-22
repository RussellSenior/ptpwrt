package NoCat::Source::Samba;

use NoCat::Source;
use Authen::Smb;
use strict;
use vars qw( @ISA @REQUIRED );

@ISA	    = qw( NoCat::Source );
@REQUIRED   = qw( Samba_PDC Samba_Domain );

sub authenticate_user {
    my ($self, $user_pw, $user) = @_;
    my $result = Authen::Smb::authen( $user->id, $user_pw,
	$self->{Samba_PDC}, $self->{Samba_BDC}, $self->{Samba_Domain} );

    if ($result == 0) {
	return 1;
    } else {
	return $self->log( 4, "Samba returned $result for user $user" );
    } 
}

1;
