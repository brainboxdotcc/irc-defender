#!/usr/bin/perl

#
#    IRC Defender - irc.chatspike.net
#    $Id: defender.pl 7819 2007-08-24 21:45:22Z Thunderhacker $
#    (C) Craig Edwards (brain) and various contributors, 2004-2005
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

use Socket;

$VERSION = "1.5-RC1";
$DATE = "Aug 2007";

require "./message.pl";
require "./Modules/Main.pm";

&general_init;
&check_params;
&load_config;
&init_modules;
&connect;
&daemon;
&poll;

