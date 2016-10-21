# Nmap_Scripts
Nmap script which allows you to get the cookies of a site, as long as they were setting by the http header directive "Set-Cookie". Also, the shown cookies are those whose expiration date is longer than a year.

To use this script you have to write the next command line:

nmap -p 80 --script=path/http-cookies.nse <IP-address>

Or:

nmap -p 443 --script=path/http-cookies.nse <IP-address>

The output will be something like that:

![alt tag](https://github.com/ernsferrari/Nmap_Scripts/blob/master/Images/http-cookies.png)
