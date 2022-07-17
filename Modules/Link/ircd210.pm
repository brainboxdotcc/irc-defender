# ircd 2.10 link module by Brain, July 2005.
# $Id: ircd210.pm 1617 2005-07-07 19:08:45Z brain $

# forward lookup nick->host
my %hosts = ();
# reverse lookup host->nick
my %nicks = ();

# emulated glines (ugh, this ircd doesnt support ANYTHING)
my %glines = ();

sub link_init
{
        if (!main::depends("core-v1")) {
                print "This module requires version 1.x of defender.\n";
                exit(0);
        }
        main::provides("server","ircd210-server","emulated-glines","emulated-globops");
	if (($numeric < 1) || ($numeric > 255)) {
		print "\n\nYour server numeric doesn't look quite right.\n";
		print "Try editing your config file again, and set your\n";
		print "server numeric to a value between 1 and 255 which\n";
		print "is not being used by another server on your network\n\n";
		exit(0);
	}
}

sub rawirc
{
	my $out = $_[0];
	my $first = "$out\n\r";
	syswrite(SH, $first, length($first));
	print ">> $out\n" if $debug;
}

sub mode
{
        my ($dest,$line) = @_;
        $line = ":$servername MODE $dest $line";
        &rawirc($line);
}

sub privmsg
{
	my $nick = $_[0];
	my $msg = $_[1];
	my $first = ":$botnick PRIVMSG $nick :$msg\n\r";
	syswrite(SH, $first, length($first));
}


sub notice
{
	my $nick = $_[0];
	my $msg = $_[1];
	my $first = ":$servername NOTICE $nick :$msg\n\r";
	syswrite(SH, $first, length($first));
}

sub message
{
	my $line = shift;
	$line = ":$botnick PRIVMSG $mychan :$line";
	&rawirc($line);
}

sub globops
{
	my $msg = $_[0];
	&rawirc(":$botnick NOTICE \$*.$domain :$msg");
}

sub message_to
{
        my ($dest,$line) = @_;
        $line = ":$botnick PRIVMSG $dest :$line";
        &rawirc($line);
}


sub killuser
{
        my($nick,$reason) = @_;
        &rawirc(":$botnick KILL $nick :$botnick ($reason)");
	$KILLED++;
}

sub gline
{
	my($hostname,$duration,$reason) = @_;
	my ($ident,$host) = split("@",$hostname);
	my $expire = time + $duration;
	# we don't support wildcards :/
	$glines{$host}{host} = $host;
	$glines{$host}{reason} = $reason;
	$glines{$host}{expire} = $expire;
	print "GLINE Lookup: $host\n";
	my $nicktokill = $nicks{lc($host)};
	&rawirc(":$servername KILL $nicktokill :*** Banned ($reason)");
	$KILLED++;
}

sub gethost
{
	my($nick) = @_;
	$nick = lc($nick);
	return $hosts{$nick};
}

sub isoper
{
	my($nick) = @_;
	if ($hosts{lc($nick)}{isoper}) {
		return 1;
	} else {
		return 0;
	}
}

sub getmatching
{
	my @results = ();
	my($re) = @_;
	foreach my $mask (%hosts) {
		if (defined($hosts{$mask})) {
			if ($hosts{$mask} =~ /$re/i) {
				push @results, $mask;
			}
		}
	}
	return @results;
}

sub connect {
	$CONNECT_TYPE = "Server";

	print ("Creating socket...\n");
        socket(SH, PF_INET, SOCK_STREAM, getprotobyname('tcp')) || print "socket() failed: $!\n";
        if (defined($main::dataValues{"bind"})) {
		print "Bound to ip address: " . $main::dataValues{"bind"} . "\n";
                bind(SH, sockaddr_in(0, inet_aton($main::dataValues{"bind"})));
        }
        else {
		bind(SH, sockaddr_in(0, INADDR_ANY));
        }

	print ("Connecting to $server\:$port...\n");
        my $sin = sockaddr_in ($port,inet_aton($server));
        connect(SH,$sin) || print "Could not connect to server: $!\n";

	print ("Logging in...\n");
	&rawirc("PASS $password 0210 IRC|AaEfiIJMu P");
	&rawirc("SERVER $servername 0 $numeric :$serverdesc");

	print ("Introducing pseudoclient: $botnick...\n");
	&rawirc("NICK $botnick 1 $botnick $domain 1 +oiw :$botname");

	print ("Joining channel...\n");
	&rawirc("NJOIN $mychan :\@$botnick");

	$njservername = $servername;
	$njtime = time+40;
	$NETJOIN = 1;

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

my $njtime = time+20;

sub checkmodes
{
        # this sub checks a nick's modes to see if theyre an oper or not
        # if they have +o theyre judged as being oper, and are inserted
        # into an @opers list which is used by non-native globops.
        my ($nick,$modes) = @_;
        if ($modes =~ /^\+/) { # adding modes
                if ($modes =~ /^\+.*(o).*$/) {
                        $hosts{lc($nick)}{isoper} = 1;
                }
        }
        if ($modes =~ /^-/) { # taking modes
                if ($modes =~ /^-.*(o).*$/) {
                        $hosts{lc($nick)}{isoper} = 0;
                }
        }
}


sub poll {

	$KILLED = 0;
	$CONNECTS = 0;

	while (chomp($buffer = <SH>))
	{
		chop($buffer);

		print "<< $buffer\n" if $debug;

		if (($NETJOIN != 0) && (time > $njtime))
	        {
                	$NETJOIN = 0;
	                print "$njservername completed NETJOIN state (merge time exceeded)\n";
        	}

		
                if ($buffer =~ /KICK/i)
                {
                        &rawirc(":$botnick JOIN $mychan");
                }

		if ($buffer =~ /^ERROR :(.+?)$/)
		{
			print "ERROR received from ircd: $1\n";
			print "You might need to check your C/N lines or link block on the ircd, or port number you are using.\n";
			exit(0);
		}

		# :Brain4 NICK [Brain]
		if ($buffer =~ /^:(.+?) NICK (.+?)$/)
		{
			$oldnick = quotemeta($1);
			$newnick = quotemeta($2);

			$hosts{lc($2)} = $hosts{lc($1)};
			delete $nicks{$hosts{lc($1)}};
			$nicks{$hosts{lc($2)}} = $2;

			foreach $mod (@modlist) {
				eval ("Modules::Scan::" . $mod ."::handle_nick(\"$oldnick\",\"$newnick\")");
			}
		}

		# NICK anon3_ 1 ~brain neuron 1 +i :Craig Edwards
		if ($buffer =~ /^NICK (.+?) .+? (.+?) (.+?) .+? (.+?) :(.+?)$/)
		{
			$thenick = $1;
			$theident = $2;
			$thehost = $3;
			$themodes = $4;
			$thegecos = $5;
			if (defined($glines{$thehost}{host})) {
					if (time() > $glines{$thehost}{expire}) {
						globops("Expiring defender ban: " . $glines{$thehost}{host});
						delete $glines{$thehost};
					} else {
						killuser($thenick,"*** Banned (".$glines{$thehost}{reason}.")");
					}
			}
			if (!defined($glines{$thehost}{host})) {
				$CONNECTS++;
				$hosts{lc($thenick)} = "$theident\@$thehost";
				$nicks{lc($thehost)} = $thenick;
				&checkmodes($thenick,$themodes);

				$thegecos = quotemeta($thegecos);
				$thenick = quotemeta($thenick);
				foreach $mod (@modlist) {
				        my $func = ("Modules::Scan::" . $mod . "::scan_user(\"$theident\",\"$thehost\",\"$theserver\",\"$thenick\",\"$thegecos\",0)");
				        eval $func;
					print $@ if $@;
				}
			}
		}
		if ($buffer =~ /^\:(.+?)\sMODE\s(.+?)\s(.+?)$/)
		{
			$thenick = $1;
			$thetarget = $2;
			$params = $3;
			$params =~ s/^\://;
			&checkmodes($thetarget,$params);
			$thenick = quotemeta($thenick);
			$thetarget = quotemeta($thetarget);
			$params = quotemeta($params);
			foreach $mod (@modlist) {
				my $func = ("Modules::Scan::" . $mod . "::handle_mode(\"$thenick\",\"$thetarget\",\"$params\")");
				eval $func;
			}
		}
		# :[Brain] TOPIC #chatspike [Brain] 1099522169 :moo moo
                if ($buffer =~ /^\:(.+?)\sTOPIC\s(.+?)\s:(.+?)$/)
                {
                        $thenick = $1;
                        $thetarget = $2;
                        $params = $3;
                        $params =~ s/^\://;
                        $thenick = quotemeta($thenick);
                        $thetarget = quotemeta($thetarget);
                        $params = quotemeta($params);
                        foreach $mod (@modlist) {
                                my $func = ("Modules::Scan::" . $mod . "::handle_topic(\"$thenick\",\"$thetarget\",\"$params\")");
                                eval $func;
                        }
                }

		# :[Brain] KILL Defender :NetAdmin.chatspike.net![Brain] (kill test)
		if ($buffer =~ /^\:(.+?)\sKILL\s(.+?)\s:(.+?)$/)
		{
			my $killedby = $1;
			my $killnick = $2;
			my $killreason = $3;
			if ($killnick =~ /^\Q$botnick\E$/i)
			{
				&rawirc("NICK $botnick 1 $botnick $domain 1 +oiw :$botname");
				&rawirc(":$botnick JOIN :$mychan");
				&rawirc(":$servername KILL $killedby :$servername (Do \002NOT\002 kill $botnick!)");
			}
		}

		if ($buffer =~ /^:(.+?)\sQUIT\s:(.+?)$/)
		{
			my $quitnick = $1;
			my $quitreason = $2;
			delete $hosts{$quitnick};
		}

		if ($buffer =~ /^:(.+?)\sJOIN\s:(.+?)$/)
		{
			$thenick = $1;
			$thetarget = $2;
			#chop($thetarget);
			$thenick = quotemeta($thenick);
			# deal effectively with multiple chan joins
			my @chanlist = split(',',$thetarget);
			foreach my $chan (@chanlist) {
				$chan = quotemeta($chan);
				foreach $mod (@modlist) {
					my $func = ("Modules::Scan::" . $mod . "::handle_join(\"$thenick\",\"$chan\")");
					eval $func;
				}
			}
		}
                if ($buffer =~ /^:(.+?)\sNJOIN\s(.+?)\s:(.+?)$/)
                {
                        $thenick = $3;
                        $thetarget = $2;
                        $thetarget = quotemeta($thetarget);
                        # deal effectively with multiple chan joins
                        my @nicklist = split(',',$thenick);
                        foreach my $nick (@nicklist) {
				$nick =~ s/^(\+|\@)//g;
                                $xnick = quotemeta($nick);
                                foreach $mod (@modlist) {
                                        my $func = ("Modules::Scan::" . $mod . "::handle_join(\"$xnick\",\"$thetarget\")");
                                        eval $func;
                                }
                        }
                }

		
		if ($buffer =~ /^:(.+?)\sPART\s(.+?)\s:(.+?)$/)
		{
			$thenick = $1;
			$thetarget = $2;
			if ($thetarget =~ / /) {
				$thetarget = split(" ",$thetarget);
			}
			$thenick = quotemeta($thenick);
			my @chanlist = split(',',$thetarget);
			foreach my $chan (@chanlist) {
				$chan = quotemeta($chan);
				foreach $mod (@modlist) {
					my $func = ("Modules::Scan::" . $mod . "::handle_part(\"$thenick\",\"$thetarget\")");
					eval $func;
				}
			}
		}
		elsif ($buffer =~ /^:(.+?)\sPART\s(.+?)$/)
		{
                        $thenick = $1;
                        $thetarget = $2;
                        if ($thetarget =~ / /) {
                                $thetarget = split(" ",$thetarget);
                        }
                        $thenick = quotemeta($thenick);
                        my @chanlist = split(',',$thetarget);
                        foreach my $chan (@chanlist) {
                                $chan = quotemeta($chan);
                                foreach $mod (@modlist) {
                                        my $func = ("Modules::Scan::" . $mod . "::handle_part(\"$thenick\",\"$thetarget\")");
                                        eval $func;
                                }
                        }
		}

		if ($buffer =~ /^SERVER\s(.+?)\s(.+?)\s:(.+?)/)
		{
			$NETJOIN = 1;
			$njservername = $2;
			print "$njservername joined the net and began syncing\n";
			$njtime = time+40;
		}

		if ($buffer =~ /^:(.+?)\sNOTICE\s(.+?)\s:(.+?)$/)
		{
			&noticehandler($buffer);
		}
		elsif ($buffer =~ /^:(.+?)\sPRIVMSG\s(.+?)\s:(.+?)$/) {
			&msghandler($buffer);
		}
		elsif ($buffer =~ /^:(.+) WHOIS (.+) :.+$/) {
			$source = $1;
			# :bender.chatspike.net 320 [Brain] [Brain] :has whacked 33 virus drones
                        main::rawirc(":$servername 311 $source $botnick $botnick $domain * :$botname");
                        main::rawirc(":$servername 312 $source $botnick $servername :$serverdesc");
                        main::rawirc(":$servername 320 $source $botnick :Is your benevolent protector");
                        main::rawirc(":$servername 318 $source $botnick :End of /WHOIS list.");

		}
		else
		{
		        if (substr($buffer,0,4) =~ /PING/i)
			{
			        &pingreply($buffer);
       			}
		}
	}
	&reconnect;
}


# sig handler

sub shutdown {
	#print "SIGINT caught\n";
	&rawirc(":$botnick QUIT :Defender terminating");
	print("Disconnecting from irc server (SIGINT)\n");
	&rawirc(":$servername SQUIT :$quitmsg");
	close SH;
	exit;
}

sub handle_alarm
{
}

1;
