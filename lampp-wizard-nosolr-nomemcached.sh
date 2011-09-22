#!/bin/bash
# 
# Run as root (don't use sudo) with
# ./lampp-wizard.sh ; tail -f /var/log/lampp-wizard.log
# 
# StackScript Bash Library
#
# Copyright (c) 2010 Linode LLC / Christopher S. Aker <caker at linode dot com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, 
# are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice, this
# list of conditions and the following disclaimer in the documentation and/or
# other materials provided with the distribution.
#–
# * Neither the name of Linode LLC nor the names of its contributors may be
# used to endorse or promote products derived from this software without specific prior
# written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
# SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.
# 
# Script modified by Luis Elizondo to suit my needs lelizondo at gmail dot com

###########################################################
# System
###########################################################

function get_ubuntu_version {
    VER=$(grep DISTRIB_RELEASE /etc/lsb-release | cut -d'=' -f2)
    echo ${VER}
}

function get_ubuntu_version_name {
    NAME=$(grep DISTRIB_CODENAME /etc/lsb-release | cut -d'=' -f2)
    echo ${NAME}
}

function logit {
	# Simple logging function that prepends an easy-to-find marker '=> ' and a timestamp to a message
	TIMESTAMP=$(date -u +'%m/%d %H:%M:%S')
    MSG="=> ${TIMESTAMP} $1"
    echo ${MSG}
}

function system_update {
	aptitude update
	aptitude -y full-upgrade
	
	REL_NAME=$(get_ubuntu_version_name)
	
	# There's a problem with PHP 5.3, most modules won't work with it
	# Please read http://groups.drupal.org/node/72718
  



  apt-get -y update
}

function update_sources {
	echo 
    logit "Setting up apt sources and applying updates"
    REL_NAME=$(get_ubuntu_version_name)
    #Enable universe
    sed -i 's/^#\(.*\) universe/\1 universe/' /etc/apt/sources.list

    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 8C6C1EFD
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 98932BEC
    apt-get -y update
		apt-get -y remove --purge language-pack-en-base
    apt-get -y install language-pack-en-base
    dpkg-reconfigure locales
    apt-get -y upgrade
    # apt-get -y dist-upgrade
    
    logit "Done setting up apt sources and applying updates"
}

function system_primary_ip {
	# returns the primary IP assigned to eth0
	echo $(ifconfig eth0 | awk -F: '/inet addr:/ {print $2}' | awk '{ print $1 }')
}

function get_rdns {
	# calls host on an IP address and returns its reverse dns

	if [ ! -e /usr/bin/host ]; then
		aptitude -y install dnsutils > /dev/null
	fi
	echo $(host $1 | awk '/pointer/ {print $5}' | sed 's/\.$//')
}

function get_rdns_primary_ip {
	# returns the reverse dns of the primary IP assigned to this system
	echo $(get_rdns $(system_primary_ip))
}

###########################################################
# Postfix
###########################################################

function postfix_install_loopback_only {
	# Installs postfix and configure to listen only on the local interface. Also
	# allows for local mail delivery

	echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
	echo "postfix postfix/mailname string localhost" | debconf-set-selections
	echo "postfix postfix/destinations string localhost.localdomain, localhost" | debconf-set-selections
	apt-get -y remove --purge postfix
	apt-get -y install postfix
	/usr/sbin/postconf -e "inet_interfaces = loopback-only"
	#/usr/sbin/postconf -e "local_transport = error:local delivery is disabled"

	touch /tmp/restart-postfix
}

###########################################################
# Apache
###########################################################

function apache_input {
	echo -n "Fully Qualified Domain Name: "
	read -e FQDN
}

function apache_install {
echo
	logit "Installing apache"
	# installs the system default apache2 MPM
	apt-get -y remove --purge apache2
	apt-get -y install apache2

	a2dissite default # disable the interfering default virtualhost

	# clean up, or add the NameVirtualHost line to ports.conf
	sed -i -e 's/^NameVirtualHost \*$/NameVirtualHost *:80/' /etc/apache2/ports.conf
	if ! grep -q NameVirtualHost /etc/apache2/ports.conf; then
		echo 'NameVirtualHost *:80' > /etc/apache2/ports.conf.tmp
		cat /etc/apache2/ports.conf >> /etc/apache2/ports.conf.tmp
		mv -f /etc/apache2/ports.conf.tmp /etc/apache2/ports.conf
	fi
	
	logit "Done installing apache"
}

function apache_tune {
echo
	logit "Tunning apache"
	# Tunes Apache's memory to use the percentage of RAM you specify, defaulting to 40%

	# $1 - the percent of system memory to allocate towards Apache

	if [ ! -n "$1" ];
		then PERCENT=40
		else PERCENT="$1"
	fi
	
	apt-get -y remove --purge apache2-mpm-prefork
	apt-get -y install apache2-mpm-prefork
	PERPROCMEM=10 # the amount of memory in MB each apache process is likely to utilize
	MEM=$(grep MemTotal /proc/meminfo | awk '{ print int($2/1024) }') # how much memory in MB this system has
	MAXCLIENTS=$((MEM*PERCENT/100/PERPROCMEM)) # calculate MaxClients
	MAXCLIENTS=${MAXCLIENTS/.*} # cast to an integer
	sed -i -e "s/\(^[ \t]*MaxClients[ \t]*\)[0-9]*/\1$MAXCLIENTS/" /etc/apache2/apache2.conf

	touch /tmp/restart-apache2
	
	logit "Done tunning apache"
}

function apache_virtualhost {
echo
	
	logit "Configuring virtualhost"
	# Configures a VirtualHost

	# $1 - required - the hostname of the virtualhost to create
	# $1 = $FQDN
	rm -f /etc/apache2/sites-available/$FQDN
	
	if [ ! -n "$FQDN" ]; then
		echo "apache_virtualhost() requires the hostname as the first argument"
		return 1;
	fi

	if [ -e "/etc/apache2/sites-available/$FQDN" ]; then
		echo /etc/apache2/sites-available/$FQDN already exists..
		return;
	fi

	rm -Rf /srv/www
	mkdir -p /srv/www/$FQDN/public_html /srv/www/$FQDN/logs

	echo "<VirtualHost *:80>" > /etc/apache2/sites-available/$FQDN
	echo "    ServerName $FQDN" >> /etc/apache2/sites-available/$FQDN
	echo "    DocumentRoot /srv/www/$FQDN/public_html/" >> /etc/apache2/sites-available/$FQDN
	echo "    ErrorLog /srv/www/$FQDN/logs/error.log" >> /etc/apache2/sites-available/$FQDN
    echo "    CustomLog /srv/www/$FQDN/logs/access.log combined" >> /etc/apache2/sites-available/$FQDN
	echo "</VirtualHost>" >> /etc/apache2/sites-available/$FQDN

	a2ensite $FQDN

	touch /tmp/restart-apache2
	
	logit "Done configuring virtualhost"
}

function apache_virtualhost_from_rdns {
	# Configures a VirtualHost using the rdns of the first IP as the ServerName

	apache_virtualhost $(get_rdns_primary_ip)
}


function apache_virtualhost_get_docroot {
	if [ ! -n "$FQDN" ]; then
		echo "apache_virtualhost_get_docroot() requires the hostname as the first argument"
		return 1;
	fi

	if [ -e /etc/apache2/sites-available/$FQDN ];
		then echo $(awk '/DocumentRoot/ {print $2}' /etc/apache2/sites-available/$FQDN )
	fi
}

###########################################################
# mysql-server
###########################################################

function mysql_input {
	echo -n "Root password for MySQL: "
	read -e DB_PASSWORD
	echo -n "Database name: "
	read -e DB_NAME
	echo -n "Database user: "
	read -e DB_USER
	echo -n "Database user password: "
	read -e DB_USER_PASSWORD
}

function mysql_install {
	# $1 - the mysql root password
	# $1 = $DB_PASSWORD

	if [ ! -n "$DB_PASSWORD" ]; then
		echo "mysql_install() requires the root pass as its first argument"
		return 1;
	fi

	echo "mysql-server-5.1 mysql-server/root_password password $DB_PASSWORD" | debconf-set-selections
	echo "mysql-server-5.1 mysql-server/root_password_again password $DB_PASSWORD" | debconf-set-selections
	# To avoid mysql asking questions, we remove it first and then install it
	apt-get -y remove --purge mysql-server mysql-client
	apt-get -y install mysql-server mysql-client

	echo "Sleeping while MySQL starts up for the first time..."
	sleep 5
}

function mysql_tune {
	# Tunes MySQL's memory usage to utilize the percentage of memory you specify, defaulting to 40%

	# $1 - the percent of system memory to allocate towards MySQL

	if [ ! -n "$1" ];
		then PERCENT=40
		else PERCENT="$1"
	fi

	sed -i -e 's/^#skip-innodb/skip-innodb/' /etc/mysql/my.cnf # disable innodb - saves about 100M

	MEM=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo) # how much memory in MB this system has
	MYMEM=$((MEM*PERCENT/100)) # how much memory we'd like to tune mysql with
	MYMEMCHUNKS=$((MYMEM/4)) # how many 4MB chunks we have to play with

	# mysql config options we want to set to the percentages in the second list, respectively
	OPTLIST=(key_buffer sort_buffer_size read_buffer_size read_rnd_buffer_size myisam_sort_buffer_size query_cache_size)
	DISTLIST=(75 1 1 1 5 15)

	for opt in ${OPTLIST[@]}; do
		sed -i -e "/\[mysqld\]/,/\[.*\]/s/^$opt/#$opt/" /etc/mysql/my.cnf
	done

	for i in ${!OPTLIST[*]}; do
		val=$(echo | awk "{print int((${DISTLIST[$i]} * $MYMEMCHUNKS/100))*4}")
		if [ $val -lt 4 ]
			then val=4
		fi
		config="${config}\n${OPTLIST[$i]} = ${val}M"
	done

	sed -i -e "s/\(\[mysqld\]\)/\1\n$config\n/" /etc/mysql/my.cnf

	touch /tmp/restart-mysql
}

function mysql_create_database {
	# $1 - the mysql root password
	# $1 = $DB_PASSWORD
	# $2 - the db name to create
	# $2 = $DB_NAME

	if [ ! -n "$DB_PASSWORD" ]; then
		echo "mysql_create_database() requires the root pass as its first argument"
		return 1;
	fi
	if [ ! -n "$DB_NAME" ]; then
		echo "mysql_create_database() requires the name of the database as the second argument"
		return 1;
	fi

	echo "CREATE DATABASE $DB_NAME;" | mysql -u root -p$DB_PASSWORD
}

function mysql_create_user {
	# $1 - the mysql root password
	# $1 = $DB_PASSWORD
	# $2 - the user to create
	# $2 = $DB_USER
	# $3 - their password
	# $3 = $DB_USER_PASSWORD

	if [ ! -n "$DB_PASSWORD" ]; then
		echo "mysql_create_user() requires the root pass as its first argument"
		return 1;
	fi
	if [ ! -n "$DB_USER" ]; then
		echo "mysql_create_user() requires username as the second argument"
		return 1;
	fi
	if [ ! -n "$DB_USER_PASSWORD" ]; then
		echo "mysql_create_user() requires a password as the third argument"
		return 1;
	fi

	echo "CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD';" | mysql -u root -p$DB_PASSWORD
}

function mysql_grant_user {
	# $1 - the mysql root password
	# $1 = $DB_PASSWORD
	# $2 - the user to bestow privileges 
	# $2 = $DB_USER
	# $3 - the database
	# $3 = $DB_NAME

	if [ ! -n "$DB_PASSWORD" ]; then
		echo "mysql_create_user() requires the root pass as its first argument"
		return 1;
	fi
	if [ ! -n "$DB_USER" ]; then
		echo "mysql_create_user() requires username as the second argument"
		return 1;
	fi
	if [ ! -n "$DB_NAME" ]; then
		echo "mysql_create_user() requires a database as the third argument"
		return 1;
	fi

	echo "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';" | mysql -u root -p$DB_PASSWORD
	echo "FLUSH PRIVILEGES;" | mysql -u root -p$DB_PASSWORD

}

###########################################################
# PHP functions
###########################################################

function php_install_with_apache {
echo
  logit "Installing PHP"
  apt-get -y update
	apt-get -y remove --purge php5 php5-mysql libapache2-mod-php5 php-pear ffmpeg
	apt-get -y install php5 php5-mysql libapache2-mod-php5 php-pear ffmpeg
	touch /tmp/restart-apache2
	
	logit "Done installing PHP"
}

function php_tune {
echo
  logit "Tunning PHP"

	# Tunes PHP to utilize up to 32M per process

	sed -i'-orig' 's/memory_limit = [0-9]\+M/memory_limit = 128M/' /etc/php5/apache2/php.ini
	sed -i'-orig' 's/upload_max_filesize = [0-9]\+M/upload_max_filesize = 256M/' /etc/php5/apache2/php.ini
	sed -i'-orig' 's/post_max_size = [0-9]\+M/post_max_size = 256M/' /etc/php5/apache2/php.ini
	
	touch /tmp/restart-apache2
	
	logit "Done tunning PHP"
}

###########################################################
# Other niceties!
###########################################################

function goodstuff {
echo

  logit "Installing Git and subversion"
	# Installs the REAL vim, wget, less, and enables color root prompt and the "ll" list long alias
	apt-get -y autoremove
	apt-get -y remove --purge wget vim less git-core subversion bzr php5-dev php5-cli php5-gd unzip curl tomcat6 bzrtools python-bzrlib python-crypto python-paramik bzr-gtk bzr-svn bzr-doc python-testtools librsvg2-bin graphviz xdg-utils python-kerberos python-crypto-dbg
	apt-get -y install wget vim less git-core subversion bzr php5-dev autoconf automake autotools-dev binutils gcc gcc-4.4 libc-dev-bin libc6-dev libgomp1 libltdl-dev libltdl7 libssl-dev libtool linux-libc-dev m4 manpages-dev shtool zlib1g-dev php5-cli php5-gd unzip curl tomcat6 bzrtools python-bzrlib python-crypto python-paramik bzr-gtk bzr-svn bzr-doc python-testtools librsvg2-bin graphviz xdg-utils python-kerberos python-crypto-dbg
	logit "Installing Bzr"
	apt-get -y install bzr
	sed -i -e 's/^#PS1=/PS1=/' /root/.bashrc # enable the colorful root bash prompt
	sed -i -e "s/^#alias ll='ls -l'/alias ll='ls -al'/" /root/.bashrc # enable ll list long alias <3
	
	logit "Done installing Git and subversion"
}


###########################################################
# utility functions
###########################################################

function restartServices {
	# restarts services that have a file in /tmp/needs-restart/

	for service in $(ls /tmp/restart-* | cut -d- -f2); do
		/etc/init.d/$service restart
		rm -f /tmp/restart-$service
	done
}

function randomString {
	if [ ! -n "$1" ];
		then LEN=20
		else LEN="$1"
	fi

	echo $(</dev/urandom tr -dc A-Za-z0-9 | head -c $LEN) # generate a random string
}
                                                                
###########################################################
# Phanteon Mercury
# Original script was written by Justin Ellison <justin@techadvise.com>
# Modifications by Luis Elizondo <lelizondo@gmail.com>
###########################################################

function drush_install {
 
    echo
    logit "Installing drush"
		rm -Rf /usr/local/drush
		rm -Rf /usr/local/bin/drush
    cd /usr/local && git clone --branch 7.x-4.x http://git.drupal.org/project/drush.git
    #if [ ! -f /tmp/drush/drush ]; then
    #    echo "Could not checkout drush from git"
    #    exit 1                            
    #fi
 
    cd /usr/local/bin/ && ln -s /usr/local/drush/drush drush
    if [ ! -x /usr/local/bin/drush ]; then
        echo "Could not install drush in /usr/local/bin"
        exit 1                    
    fi
 
    logit "Done installing drush"
}

function drush_make_install {
	echo
	logit "Installing drush make"
	cd /etc/
	rm -Rf /etc/drush
	mkdir drush
	cd drush
	git clone --branch 6.x-2.x http://git.drupal.org/project/drush_make.git
	
	logit "Done installing drush make"
}

# Not sure if needed
function get_branch {
	if [ "${PANTHEON_BRANCH}" == "1" ]; then
		echo "1.0"
	else
      echo ${PANTHEON_BRANCH}
    fi
}

function set_fqdn {
	logit "Setting FQDN to $1"
	FQDN=$1
	HOSTNAME=`echo "${FQDN}" | cut -d'.' -f1`
	DOMAINNAME=`echo "${FQDN}" | cut -d'.' -f2-`
	logit "Hostname is ${HOSTNAME}, domain name is ${DOMAINNAME}"
	echo "${HOSTNAME}" > /etc/hostname
    sed -i "s/domain .*/domain ${DOMAINNAME}/" /etc/resolv.conf
    sed -i "s/search .*/search ${DOMAINNAME}/" /etc/resolv.conf
    hostname ${HOSTNAME}
	logit "Done setting FQDN to $1"
}

function pecl_uploadprogress_install {
  # Based on http://freestylesystems.co.uk/blog/installng-pecl-uploadprogress-extension-drupal-filefield-module
  
	# Download PECL uploadprogress extension
	logit "Installing PECL uploadprogress extension"
	
	cd /tmp
	wget http://pecl.php.net/get/uploadprogress-1.0.1.tgz
	tar zxvf uploadprogress-1.0.1.tgz
	cd uploadprogress-1.0.1
	
	phpize
	./configure
	make
	make install
	
	cat <<EOD > /etc/php5/apache2/conf/uploadprogress.ini
extension=uploadprogress.so
EOD
	
	logit "Done installing PECL uploadprogress extension"
}

function user_input {
	echo -n "Administrative User: "
	read -e ADMIN_USER
	
	echo -n "Administrative User's SSH Public Key (not required): "
	read -e ADMIN_PUBKEY
}

function add_admin_user {
    USER=$ADMIN_USER
    PUBKEY=$ADMIN_PUBKEY
	# logit "Adding admin user '${ADMIN_USER}'"
    # useradd -m -G sudo ${USER}
    # mkdir -p /home/${USER}/.ssh/
    echo "${PUBKEY}" > /home/${USER}/.ssh/authorized_keys
    chown ${USER}:${USER} /home/${USER}/.ssh/authorized_keys
    chmod 600 /home/${USER}/.ssh/authorized_keys
    sed -i 's/^# %sudo/%sudo /' /etc/sudoers
	logit "Done adding admin user '${USER}'"
}

function notify_input {
	echo -n "Send Finish Notification To Email: "
	read -e NOTIFY_EMAIL
}

function webmin_install {
	logit "Installing and configuring Webmin"
	
	WEBMIN=webmin_1.510-2_all.deb
	
	rm -f /tmp/$WEBMIN
	cd /tmp
	wget http://prdownloads.sourceforge.net/webadmin/$WEBMIN
	dpkg --install /tmp/$WEBMIN
	apt-get install -f -y
	
	logit "Done installing and configuring Webmin"
}

function nfs_install {
  logit "Installing NFS Server"
	
	apt-get install -f -y nfs-kernel-server
	
	logit "Done installing and configuring NFS Server"
}

if [ -n "${ADMIN_USER}" ]; then
    if [ -n "${ADMIN_PUBKEY}" ]; then
        add_admin_user "${ADMIN_USER}" "${ADMIN_PUBKEY}"
    fi
fi

if [ -n "${FQDN}" ]; then
	set_fqdn ${FQDN}
fi

# INPUT FUNCTIONS
apache_input
user_input
mysql_input
notify_input
echo "The script has started, this could take about an hour, during the process you will not see anything. After the script is finished, an email will be sent and everything will be logged to a file in your home directory."
#exec &> /var/log/lampp-wizard.log

update_sources 
system_update
goodstuff
system_primary_ip
get_rdns
get_rdns_primary_ip
apache_install
apache_tune
mysql_install
mysql_tune
mysql_create_database
mysql_create_user
mysql_grant_user
php_install_with_apache
php_tune

pecl_uploadprogress_install
apache_virtualhost
apache_virtualhost_from_rdns
apache_virtualhost_get_docroot
restartServices
randomString
webmin_install
#nfs_install

echo
logit "Installing and configuring Postfix"
postfix_install_loopback_only
logit "Done installing and configuring Postfix"

echo "mysql-server-5.1 mysql-server/root_password password ${DB_PASSWORD}" | debconf-set-selections
echo "mysql-server-5.1 mysql-server/root_password_again password ${DB_PASSWORD}" | debconf-set-selections
#Tomcat looks for solr.war when starting, so we do solr before bcfg2
#start_BCFG2
drush_install
drush_make_install


echo
logit "Restarting services"
restartServices
logit "Done restarting services"

if [ -n "${NOTIFY_EMAIL}" ]; then
    logit "Sending notification email to ${NOTIFY_EMAIL}"
    /usr/sbin/sendmail "${NOTIFY_EMAIL}" <<EOD
To: ${NOTIFY_EMAIL}
Subject: Your Drupal installation is complete
From: LAMPP <no-reply@$FQDN>

Your Drupal installation is complete and now ready to be configured: http://$(system_primary_ip)/install.php  Select "Drupal" as your installation profile, and continue as you normally would. You can also access Webmin by going to: https://$(system_primary_ip):10000.

Enjoy Drupal!
EOD
fi

if [ -n "${NOTIFY_EMAIL}" ]; then
    logit "Sending email with log to ${NOTIFY_EMAIL}"
fi
