package NoCat::Gateway::Passive;

use NoCat qw( PERMIT DENY LOGOUT );
use NoCat::Gateway::Captive;
use vars qw( @ISA @REQUIRED );
use strict;

@ISA	    = 'NoCat::Gateway::Captive';
@REQUIRED   = @NoCat::Gateway::Captive::REQUIRED;

sub verify {
    my ( $self, $peer, $uri ) = @_;
    my $socket = $peer->socket;

    $self->log( 8, "Received notify from " . $socket->peerhost );

    # Get the user's auth ticket from the URI.
    my $content = ( $uri =~ /(?:\?|&)ticket=([^&]+)/gos )[0]
	or return $self->log( 2, "Missing notify from " . $socket->peerhost );

    $content = $self->url_decode( $content );
    
    # Add the PGP wrappers back to the ASCII armored message.
    my $msg = $self->message( 
	"-----BEGIN PGP MESSAGE-----\n\n$content\n-----END PGP MESSAGE-----" 
    );

    # Decode the message and validate the authservice's signature.
    $msg->decode
	or return $self->log( 2, "Invalid notify from " . $socket->peerhost );

    $self->log( 9, "Got auth msg:\n" . $msg->extract );

    my $auth = $self->punch_ticket( $msg, $peer->id ) or return;

    if ( $auth->{Mode} =~ /^renew/io ) {
	$self->no_response( $peer );
    } else {
	$self->redirect( $peer => $auth->{Redirect} );
    }
    return 1;
}

sub capture_params {
    my ( $self, $peer, $request ) = @_;
    return {
	mac      => $peer->id,
	token    => $peer->token, 
	redirect => $request, 
	timeout	 => $self->{LoginTimeout},
	gateway  => $peer->socket->sockhost . ":$self->{GatewayPort}"
    };
}

1;
