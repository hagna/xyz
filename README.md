If you are like me, they recently buried a server you often used behind several networks, and you wondered like I did: "Is there no *convenient* way for this client to talk to this server?"

There is a way, even a convenient way, for a client to talk to a server even if one or the other (or both) is buried in NAT--but it takes another server.  At least that's the approach taken by the programs here.  WebRTC does it too, as does TeamViewer and GoToMyPC.  Of course, a better solution probably invovles time travel to the past to replace IPv4 with IPv6.

XYZ is the name of this project which is composed of three programs named X, Y, and Z.  It easy to connect two ports on two computers using a relay server. 

                  
    client     NAT    relay    NAT     server
                |               |
      X --------|------ Y ------|-------- Z
                |               |

Figure 1.1 These three programs move or copy a TCP port, an *entire* TCP port, from one private network to another using a relay program running on a computer that is visible to both computers.



# Example

A webserver named Web has an HTTP server on port 80 in a far-off network that you want to access from your laptop (Lappy).  Using XYZ you can.

Create an accessible machine (Relay) on a provider like Digital Ocean or Amazon AWS.  For this example, Relay's IP is 99.88.77.66.

Connect Lappy to Web by doing the following:

1. Start the relay on Relay with:

        ./Y :5000

2. Connect Web's port 80 to Relay with:

        ./Z -noverify 99.88.77.66:5000 :80

3. Connect Relay to port :8080 on Lappy:

        ./X -noverify 99.88.77.66:5000 :8080

Now on Lappy you can access Web like this:

        curl http://127.0.0.1:8080



# Forwarding

A server named DMZ can access port 5432 on a server named DB in a far-off network that you want to access from your laptop (Lappy).  Using XYZ you can do this too.

Create an accessible machine (Relay) as before. For this example, Relay's IP is still 99.88.77.66.

Connect Lappy to DB by doing the following:

1. Start the relay on Relay with:

        ./Y :5000

2. Connect DB's port 5432 to Relay with:

        ./Z -noverify 99.88.77.66:5000 DB:5432

3. Connect Relay to port :8080 on Lappy:

        ./X -noverify 99.88.77.66:5000 :8080



# Authentication

The relay (Y) can authenticate X and Z clients in the following ways.  Both methods of authentication can be combined:




## Certificates

To have Y authenticate X/Z using client-side certificates, start Y with:


    ./Y -cert mycert -key mykey -ca myca :5000


Then connect X or Z in a similar manner:


    ./Z -cert mycert -key mykey -ca myca 9.8.7.6:5000 :4444


By default, X/Z will verify Y's certificate, but can be disabled with the `-noverify` option.


## Custom Authentication

To perform custom authentication use the `-auth` option.  To illustrate this, we'll run Y and Z on the same server.


Start the relay (Y) with a custom auth script:


    ./Y -auth checkpassword.sh :5000


At this point, `checkpassword.sh` has not been executed.  Next connect Z to the relay with a custom auth-submission script:


    ./Z -auth generatepassword.sh :5000 :4444


Immediately, `generatepassword.sh` is executed and the stdout is sent to Y to become the stdin in `checkpassword.sh`.  In this localhost example, it's identical to this:


    ./generatepassword.sh | ./checkpassword.sh


If `checkpassword.sh` exits with 0 authentication proceeds, otherwise authentication fails.  The stdout of `checkpassword.sh` is used to name the connected client (see Z names below).


Also, the environment variables RemoteAddr and LocalAddr are set to the remote address and local address of the connection in question.


## Authentication combinations

Y authenticating X/Z can be combined in many ways.  Here's a sampling:


1. Y will authenticate X/Z using `auth.sh`.

        ./Y -noverify -auth auth.sh :5000
        ./Z -noverify -auth sendauth.sh 9.8.7.6:5000 :443
        ./X -noverify -auth sendauth.sh 9.8.7.6:5000 :8443


2. Y will authenticate X/Z using client-side certificates.

        ./Y ca.crt :5000
        ./Z -noverify -cert mycert -key mykey -ca ca.crt 9.8.7.6:5000 :443
        ./X -noverify -cert mycert -key mykey -ca ca.crt 9.8.7.6:5000 :8443


3. Y will authenticate X/Z using client certificates first and fall back to `auth.sh` if the certificates do not verify first.

        ./Y -auth auth.sh ca.crt :5000
        ./Z -noverify -auth sendauth.sh 9.8.7.6:5000 :443
        ./X -noverify -cert mycert -key mykey -ca ca.crt 9.8.7.6:5000 :8443


X/Z can also authenticate Y.  You may have noticed that `-noverify` has been used a lot in these modest examples.  Y can also run with verifiable TLS enabled (as shown in the following command).  Then X/Z clients will verify the server by default (and must be run with -ca):

    ./Y -cert relay.crt -key relay.key -ca ca.crt :5000
    ./Z -ca ca.crt -cert mycert -key mykey 9.8.7.6:5000 :443
    ./X -ca ca.crt -cert mycert -key mykey 9.8.7.6:5000 :8443



## Z names

Z clients are named depending on the authentication method used.  In all cases, when there are name conflicts, random numbers are added.

For client-side certificate authentication, the Z name will be the common name on the certificate.

## X names

Unlike Z, for `-auth` authentication, the X name will be up to the first 30 bytes of stdout from Y running its `-auth` script, but the prefix "X:" must preceed the name.


# Multiple Servers per Relay

A single running Y program can handle many simultaneous connections from Xs and Zs.  But once there is more than one server (Z) connected, clients (X) must specify which server (Z) they want to connect to.  For instance, if we forward 2 ports:

    ./Z 9.8.7.6:5000 :3333
    ./Z 9.8.7.6:5000 :4444

Each of those connections will get a name from the relay (Y) which can be found with `./X who` (See Z names above for more information).  For instance:

    ./X who 9.8.7.6:5000
    zBQaIKhYLzbgaH
    24kbrmscmIuYuG


Connections by `X` must include the name:

    ./X 9.8.7.6:5000 :80 @zBQaIKhYLzbgaH


# Multiple Relays per X/Z


The X and Z programs may connect to more than one Y as well:

    ./Z :4000 230.90.90.90:5000 :4002 231.90.90.91:3434   
    ./X 230.90.90.90:5000 :3000 @24kbrmscmIuYuG 231.90.90.91:3434 127.0.0.1:2000
    ./X 9.8.7.6:5000 :80 @zBQaIKhYLzbgaH :9090 @24kbrmscmIuYuG 7.6.5.3:5000 :8080 @grog


# Commands TODO

The X client can also run commands on Z clients like this:

    X run [ip:port of Y] [name of client] (optional name of script)

    ./X run 230.90.90.90:5000 client1

    ./X run 230.90.90.90:5000 client1 script1

The script to run is defined like this:

    Z [port to send] [ip:port of Y] (-- [optional script] -- [optional script] ...)

    ./Z :2020 209.43.23.1:4000 -- ./script1 -- /home/frog/script2




# Usage


```
X [OPTIONS] RELAY REMOTE [RELAY REMOTE...]
X [OPTIONS] run RELAY
X [OPTIONS] who RELAY [RELAY...]
```

Where `RELAY` is `RELAY_HOST:RELAY_PORT`
Where `REMOTE` is `[BIND_ADDRESS]:BIND_PORT[ @REMOTE_NAME]`
