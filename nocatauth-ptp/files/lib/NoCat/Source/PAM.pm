package NoCat::Source::PAM;

use NoCat::Source;
use Authen::PAM qw(:constants);
use strict;
use vars qw( @ISA );

@ISA = qw( NoCat::Source );

sub converse {
    my ($self, $pw) = @_;
    return sub {
	my @res;
	while (@_) {
	    my $code = shift;
	    my $msg  = shift;
	    my $ans  = "";

	    if ($code == PAM_ERROR_MSG) {
		$self->log( 4, $msg );
	    } elsif ($code == PAM_TEXT_INFO) {
		$self->log( 9, $msg );
	    } elsif ($code == PAM_PROMPT_ECHO_OFF) {
		$ans = $pw;
	    }
	    
	    push @res, PAM_SUCCESS, $ans; 
	}
	return (@res, PAM_SUCCESS);
    };
}

sub authenticate_user {
    my ($self, $user_pw, $user) = @_;
    my $thunk  = $self->converse($user_pw);
    my $src    = Authen::PAM->new( $self->{PAM_Service} || "nocat",
	$user->id, $thunk );
    my $result = $src->pam_authenticate;

    if ($result == PAM_SUCCESS) {
	return 1;
    } else {
	return $self->log( 4, "PAM returned $result for user $user" );
    }
}

1;

