---
layout: post
title: SCTF2016 - Control Panel
categories: [ctf]
tags: [writeups, infosec, ctf]
fullview: false
comments: true
---

> Take control... of the flag on this admin control panel.

 This was an easy but pretty interesting for educational purposes. It basically gave us a link to and admin control panel web page. From there there was not much else to do but register and login.

Once in the account page, all we got was a message saying

> No flag for you. You're not an admin.

Well, not so good. In the HINTS section of the challenge it said

> There are more hints in the comments.

Pretty straightforward. Once in /account we checked the page code (CTRL+U). Somewhere in the code we found this little baby:

~~~~
<!--
Error: user.admin is not equal to true.
{
	"_id": "570880465b7ce50600883632",
	"username": "teste",
	"password": "$2a$10$.7dZbuRZUDfLOYFPvU3Lgux8crRw7Y2IUJFzZ7qINkGkS8yU34BHe",
	"uid": "2d2dhc51p4uaogoqxvmlm0rdp"
}
-->
~~~~

So, it seems the page just checks if the *admin* variable of the current user is true or not. As it is probably registered in the database, we had better send this info while registering, not logging in.

The register form sends a POST request for the server, so we must intercept it somehow and change the *admin* variable to *true*. We used *Burp Intruder* for this. Checking the request:

![req1](http://marcosvalle.github.io/assets/img/req1.png)!

There seems to be no *admin* parameter. So the default must in fact be *false*. Well, fortunately we are some bad ass space invaders and can easily change it :)

![req2](http://marcosvalle.github.io/assets/img/req2.png)!

Forwarding this crafted request redirects us once more to /account. But this time it brings a little surprise within.

![flag](http://marcosvalle.github.io/assets/img/flag.png)!

FLAG: sctf{TIL_noSql_cAn_bE_InjeKT3d_t0o}
