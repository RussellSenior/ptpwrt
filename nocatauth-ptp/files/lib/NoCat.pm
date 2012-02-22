package NoCat;

use constant VERSION	=> "0.81.20020808.20040523";
use constant PERMIT	=> "Permit";
use constant DENY	=> "Deny";
use constant PUBLIC	=> "Public";
use constant MEMBER	=> "Member";
use constant OWNER	=> "Owner";
use constant LOGOUT	=> "/logout";
use constant LOGIN	=> "/login";
use constant ANY	=> "Any";
use constant ANONYMOUS	=> "UNKNOWN";

use FindBin;
use Exporter;
use Carp;
use vars qw( @ISA @EXPORT_OK *FILE );
use strict;

@ISA	    = "Exporter";
@EXPORT_OK  = qw( PERMIT DENY PUBLIC MEMBER OWNER LOGIN LOGOUT ANY ANONYMOUS );

my %Defaults = (
    ### Gateway server networking values.
    GatewayMode	    => "Passive",
    GatewayPort	    => 5280, 
    PollInterval    => 10,
    ListenQueue	    => 10,
    HandleTimeout   => 3,
    IdleTimeout     => 300,
    MaxMissedARP    => 2,
    ForkOff	    => 1,
    ResetCmd	    => "initialize.fw",
    PermitCmd	    => 'access.fw permit $MAC $IP $Class',
    DenyCmd	    => 'access.fw deny $MAC $IP $Class',
    InitCmd	    => "reset.fw",

    ### No. of seconds before logins/renewals expire.
    LoginTimeout    => 300,
    MinLoginTimeout => 60,

    ### Fraction of LoginTimeout to loiter before renewing.
    RenewTimeout    => .75,

    ### Authservice networking values.
    DataSource	    => "DBI",
    NotifyTimeout   => 30,

    ### GPG Locations. Assumes it's in your path.
    GpgPath	    => "gpg",
    GpgvPath	    => "gpgv",
    PGPKeyPath	    => "$FindBin::Bin/../pgp",

    ### Where to look for form templates?
    DocumentRoot    => "$FindBin::Bin/../htdocs",

    ### Default log level.
    Verbosity	    => 5,
    LogFacility     => "internal",
    SyslogSocket    => "unix",
    SyslogOptions   => "pid,cons,nowait",
    SyslogPriority  => "info",
    SyslogFacility  => "user",
    SyslogIdent     => "NoCat",

    ### Stamp the version (for use in templates)
    Version	    => VERSION
);

BEGIN {
    $ENV{PATH} = $FindBin::Bin . ":" . $ENV{PATH};
}

$SIG{__WARN__} = sub { NoCat->log( 0, @_ ) };

sub new {
    my $class = shift;
    my @default = %Defaults;
    my %args = @_;

    # A couple of ways to inherit parental values...
    push @default, %$class if ref $class;    
    push @default, %{$args{Parent}} if ref $args{Parent};

    my $self = bless { @default, %args }, ref( $class ) || $class;

    # Attempt to find nocat.conf if ConfigFile is provided but undefined.
    # (i.e. the NOCAT environment variable was never set.)
    #
    if ( exists $self->{ConfigFile} ) {
	$self->{ConfigFile} ||= "$FindBin::Bin/../nocat.conf";
	$self->read_config( delete $self->{ConfigFile} );
    }

    $self->check_config;
    $self;
}

sub file {
    my ( $self, $filename ) = @_;

    $filename = $self->{$filename}
	if $self->{$filename};

    # Append the DocumentRoot if set and if the 
    # filename isn't absolute or it doesn't exist.
    #
    $filename = "$self->{DocumentRoot}/$filename"
	if $self->{DocumentRoot}
	and ( $filename !~ /^\//o or not -r $filename );

    open( FILE, "<$filename" )
	or return $self->log( 1, "file $filename: $!" );

    if ( wantarray ) {
	return <FILE>;
    } else {
	local $/ = undef; 
	return <FILE>;
    }
}

sub parse {
    my ( $self, @text ) = @_;
    my @pairs;

    for my $arg ( @text ) {
	for my $line ( split /(?:\r?\n)+/, $arg ) {
	    # Strip leading & trailing whitespace.
	    $line =~ s/^\s+|\s+$//gos;

	    # If it doesn't start with an alphanumeric, it's a comment.
	    next unless $line =~ /^\w/o;

	    # Split key / value pairs.
	    my ($key, $val) = split( /\s+/, $line, 2 );
	    push @pairs, $key, $val;
	}
    }

    return @pairs;
}

sub deparse {
    my ( $self, @vars ) = @_;
    my $text = "";

    $text .= join("\t", splice( @vars, 0, 2 )) . "\n" while @vars;
    return $text;
}

sub read_config {
    my ( $self, $filename ) = @_;

    croak "No config file specified! Does \$NOCAT point to your nocat.conf?\n"
	unless $filename;

    my $file	= $self->file( $filename ) 
	or croak "Can't read config file $filename: $!";

    my %args	= $self->parse( $file );

    $self->{$_} = $args{$_} for (keys %args);
    return $self;
}

sub check_config {
    my ( $self, @required ) = @_;
    my $class = ref( $self ) || $self;

    unless ( @required ) {
	# Try to get the @NoCat::Foo::REQUIRED list.
	no strict 'refs';
	my $req = "$class\::REQUIRED";
	@required = @$req if @$req;
    }

    # warn "CHECK $self (@required)\n";
    
    return not @required unless @required;

    my @missing = grep { not defined $self->{$_} }  @required;

    $self->log( 1, "Missing $_ directive required for $class object!" )
	for @missing;

    return not @missing;
}


sub log {
     my ( $self, $level, @msg ) = @_;

     # Bag if this message is too verbose.
     #
     if ( not ref $self or $level <= $self->{Verbosity} ) {
         if(ref $self and $self->{LogFacility} eq "syslog") {
             $self->syslog_log(@msg);
         } else {
             $self->internal_log(@msg);
         }
     }
}

sub syslog_log {
    require Sys::Syslog;

    import Sys::Syslog qw(:DEFAULT setlogsock);

    my ( $self, @msg ) = @_;

    setlogsock($self->{SyslogSocket});
    openlog($self->{SyslogIdent}, $self->{SyslogOptions}, $self->{SyslogFacility});
    syslog($self->{SyslogPriority}, "%s", "@msg");
    closelog();
}

sub internal_log {
    my ( $self, @msg ) = @_;

    # Get relevant time/date data.
    my ( $s, $m, $h, $d, $mo, $yr ) = (localtime())[0..5];
    $yr += 1900; $mo++; chomp @msg;

    # Log message takes form: [YYYY-MM-DD HH-MM-SS] *Your message here*
    print STDERR (sprintf( "[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
                           $yr, $mo, $d, $h, $m, $s, "@msg" ));
    return;
}

sub url_encode {
    my ( $self, @args ) = @_;
    for ( @args ) {
	$_ = "" unless defined $_;
	s/(\W)/sprintf("%%%02x", ord $1)/egos;
    }
    return wantarray ? @args : $args[0];
}

sub url_decode {
    my ( $self, @args ) = @_;
    s/%([0-9A-Z]{2})/chr hex $1/egios for ( @args );
    return wantarray ? @args : $args[0];
}

sub url {
    my ( $self, $url, $args )	= @_;
    my %data = $self->url_encode( %$args );
    $url  = $self->format( $self->{$url} || $url );
    $url .= ( $url =~ /\?/o ? "&" : "?" );
    $url .= join("&", map( "$_=$data{$_}", keys %data ));
    return $url;
}

sub format {
    my ( $self, $string, $extra ) = @_;

    # Merge parameters from %$extra, if any.
    my %args = $extra ? ( %$self, %$extra ) : %$self;

    # Throughout $string, replace strings of form $var or ${var} with value of $args{var}.
    $string =~ s/\$\{?(\w+)\}?/ defined( $args{$1} ) ? $args{$1} : "" /egios;

    return $string;
}

sub template {
    my ( $self, $filename, $extra ) = @_;
    my $file = $self->file( $filename );
    return $self->format( $file, $extra ); 
}

sub md5_hash {
    my ( $self, $string, $salt ) = @_;

    unless ( $salt ) {
	my @chars = ( "0".."9", "a".."z", "A".."Z", ".", "/" );
	$salt  = "";
	$salt .= @chars[int rand @chars] for ( 1 .. 8 );
    }

    $salt = '$1$' . substr( $salt, 0, 8 ) if $salt !~ /^\$1\$/o;

    return crypt( $string, $salt );
}

sub increment_token {
    my ( $self, $token ) = @_;
    my $salt = ++substr( $token, -8 );
    return $self->md5_hash( $token, $salt );
}

sub instantiate {
    my $self	= shift;
    my $class 	= shift;
    my ( $super, $config );

    if ( $super = ref $self ) {
	# $self is an object, which presumably already has the config data.
	$config = $self;	
    } else {
	# Gotta instantiate a bootstrap object to load up the config data.
	$config = __PACKAGE__->new( @_ );
	$super  = $self;
    }

    $class = "$super\::$config->{$class}";

    croak "Source class $class contains invalid characters"
	if $class =~ y/A-Za-z0-9_://cd;

    eval "require $class" or
        croak "Can't load class '$class': $@";

    return $class->new( Parent => $self, @_ );
}

sub gateway {
    my $self	  = shift;
    require NoCat::Gateway;
    return NoCat::Gateway->new( Parent => $self, @_ );
}

my $Firewall; # Singleton instance.

sub firewall {
    my $self = shift;

    # If we already have an initialized NoCat::Firewall object,
    # use it, rather than creating a new one and having to go
    # through the autodetect process all over again.

    if ( $Firewall ) {
	my %args = @_;
	%$Firewall = (%$Firewall, @_);
    } else {
	require NoCat::Firewall;
	$Firewall = NoCat::Firewall->new( Parent => $self, @_ );
    }
    return $Firewall;
}

sub auth_service {
    my $self = shift;
    require NoCat::AuthService;
    return NoCat::AuthService->new( Parent => $self, @_ );
}

sub source {
    my $self = shift;
    require NoCat::Source;
    return NoCat::Source->new( Parent => $self, @_ );
}

sub user {
    my $self = shift;
    require NoCat::User;
    return NoCat::User->new( Parent => $self, @_ );
}

sub group {
    my $self = shift;
    require NoCat::Group;
    return NoCat::Group->new( Parent => $self, @_ );
}

sub message {
    my $self = shift;
    unshift @_, "Msg" if @_ == 1;
    require NoCat::Message;
    return NoCat::Message->new( Parent => $self, @_ );
}

sub peer {
    my $self = shift;
    unshift @_, "Socket" if @_ == 1;
    require NoCat::Peer;
    return NoCat::Peer->new( Parent => $self, @_ );
}

1;

__END__

=head1 NAME

NoCat - Common Library and parent object for NoCat Authorization and Administration Services.

NoCat.pm contains constructor methods for:

NoCat::AuthService
NoCat::Firewall
NoCat::Gateway
NoCat::Message
NoCat::Peer
NoCat::User

=head1 SYNOPSIS

 use lib '/usr/local/nocat/lib'; 
 use NoCat;

 my $authserv = NoCat->auth_service( ConfigFile => '' );
 my $firewall = NoCat->firewall( ConfigFile => $ENV{NOCAT} );
 my $gateway  = NoCat->gateway( ConfigFile => $ENV{NOCAT} );
 my $message  = NoCat->message( ConfigFile => $ENV{NOCAT} );
 my $peer     = NoCat->peer( ConfigFile => $ENV{NOCAT} );
 my $user     = NoCat->user( ConfigFile => $ENV{NOCAT} );

=head1 DESCRIPTION 

This is wonderful Magick.  

=head1 METHODS 

=item new() Constructor  (do not call directly)

=item file() Reads and return a text file.  

Will read the passed file, and will attempt to add the Document_Root 
to the file name when Document_Root exists (ie. when run as a CGI).

  $user = NoCat->user( ConfigFile => ... );

  $st = $user->file( '/usr/local/nocat/nocat.conf' );

	or

  @lines = $user->file( '/usr/local/nocat/nocat.conf' );

=item parse() Splits an array of lines into an array of key->value pairs 

Used internally by configuration mechanism

=item deparse() The opposite of parse.  Joins an array of key->value pairs into
an array of conifiguration file ready lines. 

=item read_config() Reads a NoCat configuration file and loads the key->value
pairs into the current $self object namespace hash.

 For Example:  Assume these lines are in the config file test.conf:
 key1   value1
 key2   value2

 Running this code:

 $user = NoCat::user(ConfigFile => '' );
 $user->read_config('test.conf');
 print "$user->{key1}\n";
 print "$user->{key2}\n";

 will first cause the default nocat.conf to be loaded, and then load the 
 additional config file 'test.conf' and display the values from test.conf:

 value1
 value2

 (In addition to a variable number of debug messages, see 'Verbosity' in nocat.conf)

=item check_config() Checks the sub-class defined @REQUIRED list for mandatory config
file variables.  Fails, loudly, if any required config variables are not defined. 

=item log() Display a message.
  This will display the message as long as $verbosity is below the value of Verbosity in nocat.conf

  $user->log( $verbosity, 'My Message' );
   
=item url_encode() Do basic url encoding of each parameter.  Return list or first element depending on context.

Do not use on a complete url string like 'http://www.nocat.org/test.cgi?k1=value1&k2=value2, rather, call url_encode
on each parameter, in turn, and then assemble the url string.

=item url_decode() Reverse url_encode. 

=item format() Fill a template of form $var with the values of $self->{var}, plus you can pass an additional 
hashref of additional values to be substituted.   Called from template()

=item template() Pass a template, and optional hashref, and it returns the filled template. 

=item gateway() Returns a NoCat::Gateway object

=item firewall() Returns a NoCat::Firewall object

=item auth_service() Returns a NoCat::AuthService object

=item user() Returns a NoCat::Gateway object

=item message() Returns a NoCat::Message object

=item peer() Returns a NoCat::Peer object

=head1 CONFIGURATION

The NoCat system uses the configuration file found in $ENV{NOCAT} by default.
You may also pass all of the constructors a ConfigFile parameter to specify
the location of your ocnfiguration file.  If you use an empty value for 'ConfigFile'
then the system will search for nocat.conf in the directory above your script.

The Format of the config file is: <Directive> <Value>, one per
line. Trailing and leading whitespace is ignored. Any
line beginning with a punctuation character is assumed to
be a comment.

=head1 SEE ALSO

 NoCat::AuthService
 NoCat::Firewall
 NoCat::Gateway
 NoCat::Message
 NoCat::Peer
 NoCat::User

=head1 AUTHORS

Schuyler Erle (SDE) & Robert Flickenger (RJF). Documentation written by Rich Gibson.

