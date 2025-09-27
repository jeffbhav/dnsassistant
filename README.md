# dnsassistant
DNS Assistant single user version
Monitor your portfolio of domains by bulk checking dns changes and bulk checking whois changes with some stats.

Intall on your local PC running windows with WSL or PC running Linux.
Copy to a directory where you want to run it.
Edit config.ini file to your liking:

Run
The app will track DNS changes for domains in the system. To track the changes you need to specify:

(Example)
successful_nameserver_patterns = godaddy.com
unsuccessful_nameserver_patterns = sedoparking.com, parkingcrew.net, domainsponsor.com, bodis.com

successful_nameserver_patterns are the domains that belong to you. If there is a change in the DNS that means your domain DNS has changed and you need to take action.

unsuccessful_nameserver_patterns are the domains with the nameservers that you want to track other than your own.

You will need subscription to a WHOIS API provider, edit the config.ini file to add the WHOIS provider there.

You can run in a venv if you choose to, not a must.
Once you are in the command line, type python3 webapp.py then use your browser to view the UI: http://localhost:5000
To view and manage your domains.

Name of db created will be: dns_lookup_results.db. This is where all your domains will be added.
