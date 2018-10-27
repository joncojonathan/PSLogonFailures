# PSLogonFailures
`PSLogonFailures` is a PowerShell script to help mitigate brute force attacks against remote desktop servers, both those published to the public Internet and those on your internal network.  This script was developed in collaboration with my long-time friend [zandeez](https://github.com/zandeez).

Working in IT, predominantly with Microsoft Windows systems, I noticed a lot brute force attempts trying to login to servers over remote desktop via remote desktop protocol (RDP).  RDP is great for managing Windows servers and workstations but also opens the system up to attack and potential abuse.  On Linux we have tools like [Fail2Ban](https://www.fail2ban.org) to help protect against brute force attacks but I couldn't find something free at the time I initially released this script.  After I started implementing this script at customer sites the number of failed logon attempts (typically overnight) would drop to less than 10% of the pre-implementation value.

## Requirements
Please see the [requirements page](https://github.com/joncojonathan/PSLogonFailures/wiki/Requirements) on this project's wiki.

## Installation and how to
Please see the [GitHub wiki](https://github.com/joncojonathan/PSLogonFailures/wiki) for this project for more information.


## Security
Publishing (making available) part of your network to the public Internet is always a risk, and this script __is not a replacement for a well configured environment__.

* If you don't need to publish your system to the public Internet, don't
* When publishing your system, restrict it to as small a part of the Internet as possible, for example just one remote IP address or a small selection
* Only publish the _service_ you intend to access remotely (for example RDP on port TCP 3389)

## The whitelist
In order to prevent yourself from being locked out, `PSLogonFailures` allows you to specify a whitelist of individual IPs that it will never block.  You are _strongly_ encouraged to populate this list with at least one IP address.

## Why not just use product X?
Since I and [Andee](https://twitter.com/zandeez) wrote `PSLogonFailures` I've seen a number of similar solutions become available, so this is a natural question.  I'd suggest PSLogonFailures has the following benefits:

* You can review the code, so you know what it's doing
* It's free
* You can modify PSLogonFailures to meet your needs (pull requests and contributions welcomed)

## Warranty
Per the license, please be aware this script comes with __no warranty of any kind__ and the authors cannot be held liable for any problems resulting from its use.  The script has been tested on a number of systems, but every system is different.  Please ensure you know what the script will do before you run this script!

