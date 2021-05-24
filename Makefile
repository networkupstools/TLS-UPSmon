### Makefile for UPSmon.py ...
### Copyright (C) 2020 Roger Price
### Available without cost under the terms of the GNU GPL.

###   This program is free software; you can redistribute it and/or
###   modify it under the terms of the GNU General Public License
###   as published by the Free Software Foundation; either version 2
###   of the License, or (at your option) any later version.

###   This program is distributed in the hope that it will be useful,
###   but WITHOUT ANY WARRANTY; without even the implied warranty of
###   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
###   GNU General Public License for more details.

###   You should have received a copy of the GNU General Public License
###   along with this program; if not, write to the Free Software
###   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, 
###   USA.

###   See also http://www.gnu.ai.mit.edu/copyleft/gpl.html for details.

# Type "make" to place copies of the Python3 scripts in /srv/www/htdocs/NUT/

############################################################
# Build a distribution package for UPSmon.py ...
# 1999-03-08 Roger Price
# 2020-10-19 Adapted for UPSmon.py
#SERVER = /srv/www/htdocs/NUT
#SOURCE_DIR = /mnt/home/rprice/Python/UPSmon/

# 1. Check lint-free and then copy to web server
install: UPSmon.lint mkUPSmonconf.lint
#	cp $(SOURCE_DIR)UPSmon.py $(SERVER)
#	cp $(SOURCE_DIR)mkUPSmonconf.py $(SERVER)
#	cp $(SOURCE_DIR)pylintrc $(SERVER)
#	sha1sum UPSmon.py > SHA1SUMS2
#	sha1sum mkUPSmonconf.py >> SHA1SUMS2
#	sha1sum pylintrc >> SHA1SUMS2
#	cp $(SOURCE_DIR)SHA1SUMS2 $(SERVER)

# Linter in action
UPSmon.lint: UPSmon.py pylintrc
	pylint UPSmon.py
	date > UPSmon.lint

mkUPSmonconf.lint: mkUPSmonconf.py pylintrc
	pylint mkUPSmonconf.py
	date > mkUPSmonconf.lint
