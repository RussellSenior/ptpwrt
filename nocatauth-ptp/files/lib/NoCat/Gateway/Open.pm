package NoCat::Gateway::Open;

use NoCat::Gateway qw( PERMIT DENY PUBLIC );
use NoCat::BrowserDetect;
use vars qw( @ISA @REQUIRED );
use strict;

@ISA	    = 'NoCat::Gateway';
@REQUIRED   = ( @NoCat::Gateway::REQUIRED, qw( SplashForm MobileForm ));

my %MIME = (
    jpg	    => "image/jpeg",
    jpeg    => "image/jpeg",
    gif	    => "image/gif",
    png	    => "image/png",
    ico     => "image/x-icon",
    html    => "text/html",
    htm	    => "text/html",
    txt	    => "text/plain",
    css	    => "text/css"
);

sub handle {
    my ( $self, $peer )       = @_;
    my $request               = $self->read_http_request( $peer );

    if ( my $host = $request->{Host} ) {
	my $me = $peer->gateway_ip;

        $self->log( 7, "Peer", $peer->socket->peerhost, "requests $host" );

        # $self->log( 9, "HTTP headers: @{[ %$request ]}" );

        # If the request was intended for us...
        if ( $host eq $me or $host =~ /:$self->{GatewayPort}$/ ) {

            # User accepted the AUP?
	    if ( $request->{Method} eq 'POST' and $host eq $me ) {
		$self->verify ( $peer => $request );

            # User wants a status page.
            } elsif ( $request->{URI} eq "/status" ) {
		$self->status( $peer => $request );

            # User has been captured. Show them the splash page.
            } elsif ( $request->{URI} =~ /^\/\?redirect=([^&]+)/o ) {
                $request->{URL} = $self->url_decode( $1 );
                $self->splash( $peer => $request );

	    # If nothing special is requested, capture the user.
            } elsif ( $request->{URI} eq "/" ) {
                $request->{URL} = $self->{HomePage};
                $self->capture( $peer => $request );

            # Must be some other content in here.
            } else {
                $self->serve( $peer => $request );
            }
        } else {
	    # The user was trying to get out. Capture them.
	    $self->capture( $peer => $request ); 
        }
    } else {
        $self->log( 7, "No HOST header in request - Peer ", $peer->ip );
        $self->log( 9, "HTTP headers: " );
        while ((my $key, my $value) = each %$request) {
            if ( defined $value ) {
                $self->log( 9, "    $key: $value" );
            } else {
                $self->log( 9, "    $key" );
            }
        }
        $peer->socket->close;
    }
}


sub serve {
    my ( $self, $peer, $request ) = @_;

    my $file = "$self->{DocumentRoot}$request->{URI}";
    $file =~ s/\.+/./gos; # Prevent ../ type whatnot.

    my ($ext) = ( $file =~ /([^\.\/]+)$/gos ); # Try to get the file extension?
    $ext = $MIME{$ext};

    $self->log( 8, "Attempting to serve $file" );

    return $self->not_found( $peer => $request, 
	"Bad MIME type for $request->{URL}" )
	unless $ext;

    return $self->not_found( $peer => $request )
	unless -r $file and -f $file;

    # Load the file from disk.
    my $data = $self->file( $file );
    
    # Parse it automatically if it's HTML. Is this a bad idea? Why?
    $data = $self->format( $data, $self->splash_vars($peer) ) 
	if $ext eq "text/html";

    # We already know the size of the data...
    my $size = length $data;

    $peer->socket->print( 
	"HTTP/1.1 200 OK\r\n",
	"Content-type: $ext\r\n",
	"Content-length: $size\r\n\r\n",
	$data
    );
    
    $peer->socket->close;
}

sub not_found {
    my ( $self, $peer, $request, $error ) = @_;

    $self->log( 2, $error || "Unable to satisfy GET $request->{URL}" );

    $peer->socket->print( 
	"HTTP 404 Not Found\r\n\r\n",
	"The requested item could not be found."
    );

    $peer->socket->close;
}

sub capture {
    my ( $self, $peer, $request ) = @_;
    my $host	= $peer->gateway_ip;
    my $url	= $self->url_encode( $request->{URL} );

    $self->log( 8, "Capturing peer", $peer->ip );
    $self->redirect( $peer => "http://$host/?redirect=$url" );
}

sub splash {
    my ( $self, $peer, $request ) = @_;
    my $browser = new NoCat::BrowserDetect($request->{Agent});
    
    if ($browser->mobile) {
	$self->log( 5, "Client: " . $peer->ip . " " . $peer->mac . " $request->{Agent}");
	$self->log( 5, "Displaying mobile splash page to peer", $peer->ip );
        $self->respond( $peer, MobileForm => $self->splash_vars($peer, $request) )
    } else {
	$self->log( 5, "Client: " . $peer->ip . " " . $peer->mac . " $request->{Agent}");
	$self->log( 5, "Displaying splash page to peer", $peer->ip );
	$self->respond( $peer, SplashForm => $self->splash_vars($peer, $request) )
    }
}

sub splash_vars {
    my ( $self, $peer, $request ) = @_;

    $request		       ||= {};
    $request->{action}		 = "http://" . $peer->gateway_ip . "/";
    $request->{redirect}	 = $request->{URL} || $self->{HomePage};
    $request->{ConnectionCount}  = $self->peer_count;

    return $request; 
}

sub verify {
    my ( $self, $peer, $request ) = @_;
    my $socket = $peer->socket;
    my ( $line, $url );

    read( $socket, $line, $request->{"Content-length"} )
	or $self->log( 3, "Trouble reading from peer: $!" );

    $url = $self->url_decode( $1 )
	if $line =~ /(?:^|&)redirect=([^&]+)/o;
    
    if ( $url ) {
	$self->log( 5, "Opening portal for " . $peer->ip . " " . $peer->mac . " to $url" );
	$self->permit( $peer => PUBLIC );
	$self->redirect( $peer => $url ); 
    } else {
	$self->log( 5, "POST failed from " . $peer->ip );
	$self->capture( $peer => $request );
    }

}

1;
