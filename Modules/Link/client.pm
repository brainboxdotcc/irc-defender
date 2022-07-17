# $Id: client.pm 330 2004-03-28 17:15:28Z brain $

my %hosts = ();

sub link_init
{
        if (!main::depends("core-v1")) {
                print "This module requires version 1.x of defender.\n";
                exit(0);
        }
        main::provides("client","unreal-client");
}

sub rawirc
{
	my $out = $_[0];
	my $first = "$out\n\r";
	syswrite(SH, $first, length($first));
	print ">> $out\n" if $debug;
}


sub privmsg
{
	my $nick = $_[0];
	my $msg = $_[1];
	my $first = "PRIVMSG $nick :$msg\n\r";
	syswrite(SH, $first, length($first));
}

sub mode
{
        my ($dest,$line) = @_;
        $line = "MODE $dest $line";
        &rawirc($line);
}


sub notice
{
	my $nick = $_[0];
	my $msg = $_[1];
	my $first = "NOTICE $nick :$msg\n\r";
	syswrite(SH, $first, length($first));
}

sub message
{
        my $line = shift;
        $line = "PRIVMSG $mychan :$line";
        &rawirc($line);
}

sub message_to
{
        my ($dest,$line) = @_;
        $line = "PRIVMSG $dest :$line";
        &rawirc($line);
}

sub killuser
{
	my($nick,$reason) = @_;
	&rawirc("KILL $nick :$reason");
	$KILLED++;
}

sub gline
{
	my($hostname,$duration,$reason) = @_;
	&rawirc(":$botnick GLINE $hostname $duration :$reason");
	$KILLED++;
}

sub isoper
{
	# not supported
	return 0;
}

sub connect {
	$CONNECT_TYPE = "Client";

	print("Creating socket...\n");
        socket(SH, PF_INET, SOCK_STREAM, getprotobyname('tcp')) || print "socket() failed: $!\n";

	print("Connecting to $server\:$port...\n");
        my $sin = sockaddr_in ($port,inet_aton($server));
        connect(SH,$sin) || die "connect() failed: $!\n";

	print("Logging in...\n");
	&rawirc("USER $botnick * * :$botname");
	&rawirc("NICK $botnick");

	print("Oper-up...\n");
	&rawirc("OPER $oname $opass");
	&rawirc("MODE $botnick +s +cF");
	print "Joining channel...\n";

	&rawirc("SETNAME :$botname - $killtotal killed, $connects scanned");
	&rawirc("NICKSERV IDENTIFY $nspass");
	&rawirc("MODE $botnick -h+SvBWiw");
	&rawirc("CHGHOST $botnick :$domain");

	&rawirc("JOIN $mychan");

}

sub pingreply {
	$string = $_[0];
	@per = split(':', $string, 2);
	$pier = $per[1];
	$ret = "PONG :$pier";
	&rawirc($ret);
}


sub reconnect {
	close SH;
	&connect;
	&poll;
}

sub examine_user
{
        @blah = split(" ",$_[0],11);
        my $ident = @blah[4];
        my $host = @blah[5];
        my $serv = @blah[6];
        my $nick = @blah[7];
        my $fullname = @blah[10];
        chop($fullname);

	$hosts{lc($nick)} = "$ident\@$host";

        $fullname  = quotemeta($fullname);
	$nick = quotemeta($nick);
	foreach $mod (@modlist) {
             my $func = ("Modules::Scan::" . $mod . "::scan_user(\"$ident\",\"$host\",\"$serv\",\"$nick\",\"$fullname\",0)");
             eval $func;
        }

}

sub gethost
{
	my($nick) = @_;
	$nick = lc($nick);
	return $hosts{$nick};
}

sub poll {

	$KILLED = 0;
	$CONNECTS = 0;

	while (chomp($buffer = <SH>))
	{
		if ($buffer =~ /^:(.+)\s352\s/i)
		{
			$serv = $1;
			examine_user($buffer);
		}
                if ($buffer =~ /KICK/i)
                {
                        &rawirc("JOIN $mychan");
                }
		if ($buffer =~ /notice/i)
		{
                        @stuff = split(/: /,$msg);
                        $v1 = @stuff[1];
                        ($vic,undef) = split(/ /,$v1);
                        @bleh = split(" ",join(/ /,@stuff));
                        $idx = @bleh[7];
                        if ($idx !~ /\./)
                        {
                                $idx = @bleh[8];
                        }
                        $idx =~ s/\(//;
                        $idx =~ s/\)//;

                        (undef,$idx) = split('@',$idx);
                        $uhost = $idx;
                        &rawirc("who +n $vic");
			$CONNECTS++;
			&noticehandler($buffer);

		}
		elsif ($buffer =~ /^.+? PRIVMSG :.+$/) {
			&msghandler($buffer);
		}
		else
		{
		        if (substr($buffer,0,4) =~ /ping/i)
			{
			        &pingreply($buffer);
       			}
		}
	}
	&reconnect;
}


# sig handler

sub shutdown {
	print("Disconnecting from irc server...\n");
	$iout = "QUIT :$quitmsg";
	&rawirc($iout);
	close SH;
	exit;
}

sub handle_alarm
{
	# client module doesnt use an alarm handler but must
	# still define the stub function
}

1;
