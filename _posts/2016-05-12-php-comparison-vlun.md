---
layout: post
title: PHP strings comparison vulnerabilities
categories: [ctf, php]
tags: [writeups, infosec, ctf, php]
fullview: false
comments: true
---

So if I ask you this simple question: "How would you write a code to compare two strings in php?"

Let's take a look at two most obvious answers.

# str1 == str2 (Magic hashes)

~~~~~
<?php
        $str1 = "0";
        $str2 = "0e462097431906509019562988736854";

        if($str1 == $str2){
                echo "OMG twins!";
        }else{
                echo "Bieber, the king of the world";
        }
?>
~~~~~

I cannot think of anything simpler. Surprisingly enough, the result gets to be:

>OMG twins!

WTF!? Very, very weird. What happens is PHP interprets 0e as scientific notation. So our has in $str2 will be automatically casted to a numeric representation. Which representation? Yes, 0.
This is why you should never use ~~php~~ == operators but === instead. The identity (===) operator also checks the type of the operands, before evaluating.

A nice example of this vuln can be found in [this CTF](https://github.com/ctfs/write-ups-2016/tree/master/internetwache-ctf-2016/web/mess-of-hash-50)

# strcmp($str1, $str2) (Array injection)

Let's suppose now you are a smart person and are not willing to use the Equal operator. Since you have a beautiful C background, you will stick to *strcmp()* function. Nice! A function created to compare strings ~~cannot~~ should not be vulnerable when doing its job.


According to the [docs](http://php.net/manual/en/function.strcmp.php):

>strcmp(string $str1, string $str2) --> Returns < 0 if str1 is less than str2; > 0 if str1 is greater than str2, and 0 if they are equal.

Ok, so it means every time strcmp(str1, str2) is 0 the strings are equal. Hmmm... What if there was another what to make strcmp() 0? Well, what happens when we pass one string and one non-string parameter like an array to strcmp()? Right, it will result in a false statment and the result of strcmp() will be 0!. 

~~~~~
<?php
        $str1 = "pink"; 
        $str2 = array("name" => "floyd");

        if(strcmp($str1, $str2 == 0)){
                echo "OMG twins!";
        }else{
                echo "Bieber, the king of the world";
        }
?>
~~~~~

Could you see what would the result be in case we changed str2 the way it is shown above? 

>WARNING strcmp() expects parameter 2 to be string, array given on line number 5
>OMG twins!

There it is! If we pass an array instead of a string to strcmp(), it gives a warning but evaluates the result as 0. This could be very useful for bypassing logins.

Two sweet examples might be found in CTFs [here](https://ctfs.me/web/web50/) and [here](http://danuxx.blogspot.my/2013/03/unauthorized-access-bypassing-php-strcmp.html).
