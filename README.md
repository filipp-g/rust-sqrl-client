# rust-sqrl-client
Rust implementation of SQRL client

> :warning: **Note**: This application was created as an academic project
and is missing a lot of the functionality required to be effective and secure.
It is not ready for production, use at own risk.

Authors: Fil Gorodkov, Carter Struk, Austin Wright, Max Dobrei

The rust-sqrl-client is exactly what it sounds like: An SQRL client
application written in the Rust programming language.

SQRL itself is an API designed by Steve Gibson, and the basic idea is
that you can login to SQRL supported websites without ever having to give
the website a username, or password (which is the traditional method used
by almost every webapp to this day). Instead, if you have an account with
the website that is associated to an SQRL identity, the SQRL client can act
as a proxy between you and the website. You still have a password, but this
is only ever known to the SQRL client. 

The implications of never sending your username and password over the network
are twofold - firstly, in the event that the website is somehow malicious
(such as trying to sign into amaz0n.com instead of Amazon.com), you won't be
sending any sensitive information. Secondly, if you do sign into Amazon.com,
it does not have to store any sensitive information on its servers - if there
is a data breach at Amazon, the only thing the hackers recover is a public
key associated with your SQRL identity - not only is this information already
meant to be public, and therefore able to be shared with anyone without any
reprecussions, the design of the SQRL API also dictates that you have a
different public key for every website you want to use SQRL with.  In such a
way, even if they recover your public key, it cannot be linked to any other
accounts you may have associated with your SQRL identity. 

For more information about SQRL and a better explanation, you should visit
https://www.grc.com/sqrl/sqrl.htm

To build the executable (assuming your on windows):

If you have downloaded the source files, and have Rust installed, you can
enter the projects directory from a terminal and run

`cargo build`

This should compile the source code into an executable called
'rust-sqrl-client.exe'. You should be able to find the file in the
target/debug directory.

From there you can continue to use the terminal and run the command

`rust-sqrl-client.exe`

to start it up, or simply double click on the executable, which will open
up a command prompt.

USING THE APPLICATION:
-----------------------------------
You can enter 'h' to see a list of all the commands. Their use is as follows;

'0' = exit; Quit the progam.

'1' = Create Identity; Set up a new SQRL identity, which requires you to
input a password to use with the identity. Once an identity has been created,
a masterkey will have been generated, and you can start using the rest of
the programs functionality. (As of this moment we have not implemented the
secure storage part of the SQRL API, meaning you will need to create a new
identity every time you want to use the app).

'2' = Create keys for url; If you would rather input the SQRL url to the
program directly instead of clicking on the 'sign in with SQRL' button on
the website, you can copy the link from the button and enter it when prompted.
This will generate the persite public/private keypair that will be needed to
sign you in. Note: This will happen automatically if you input '3', when the
SQRL server reaches out to send its first URL. 

'3' = Start server; The SQRL client needs to have its own webserver running
in the background to communicate properly with the SQRL server and the users
browser. Once you have created an identity, you should use this command to
allow you to login using the 'Login with SQRL' button.

---------------------------------
Typical use of the application:

First, you will want to enter '1' and follow the steps to create your SQRL
identity. With that done, you can safely input '3' to start the webserver.
Once that is done, the application will handle things as necessary, with no
more user input.

At this point, you can go ahead and visit a website that has SQRL enabled
(such as https://www.grc.com/sqrl/demo.htm?).

If you so wish, you can create a dummy account on that website, and
login/logout. Unfortunately we have not implemented the step to associate
that account with the SQRL identity created by the program, and therefore
you will not be able to sign in using SQRL. 

You can click on the 'sign in with SQRL' button to see the output of our
program, however due to the reason above, at best it will redirect you to a
URL that *would* log you in if the identity was associated with an account,
but instead it gives a 'page not found' error. Otherwise, it may just keep
you on the demo page. 

