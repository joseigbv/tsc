# tsc (Simple TCP Scanner)
Simple dependency free tcp scan tool for UNIX/Linux and MS Windows

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

The tsc scanner should run on any UNIX/Linux or Win32 box. You only need a relatively modern gcc compiler. To compile for another architecture (eg Solaris SPARC) you will need a cross compiler. 
There are two versions: single or with threads.

### Installing

Download a copy of the project from github: 

```
$ git clone https://github.com/joseigbv/tsc
```

Edit 'tsc.c' and change configuration (optional).

Compile.

* linux: 
```
$ gcc -Wall -O2 tsc.c -o tsc -lpthread
```
* osx: 
```
$ gcc -Wall -O2 tsc.c -o tsc
```
* win32 (mingw): 
```
$ gcc -Wall -O2 tsc.c -o tsc -lwsock32
```
* solaris: 
```
$ gcc -Wall -O2 tsc.c -o tsc -lsocket -lnsl
```

### Usage 

The command line is very simple: 

```
$ tsc {network|filename|ip} [port,from-to]
```

Example: searching http servers

```
$ tsc ips-all.txt 80 
```

It scans port 80 for any address in ips.txt and creates an index.txt in csv format:

```
...
199.88.100.225;80;401;RomPager/4.07 UPnP/1.0
199.88.100.217;80;301;Apache/2.2.9 (Unix) mod_ssl/2.2.9 OpenSSL/0.9.7e mod_wsgi/2.4 Python/2.6.2
199.88.0.85;80;200;thttpd/2.20c 21nov01
...
```


#### Analysis:

For example, we can get a count of the http code returned by each server (top 5):

```
$ awk -F';' '{ x[$3]++ } END { for (k in x) print x[k], k }' <  index.txt | sort -nr | head -5

292957 401
237605 200
26859 302
13117 404
9133 301
```

Or "top 10" servers:

```
$ awk -F';' '{ x[$4]++ } END { for (k in x) print x[k], k }' <  index.txt | sort -nr | head -10

249709 RomPager/4.07 UPnP/1.0
124476 mini_httpd/1.19 19dec2003
58025 (n/a)
22989 RomPager/4.51 UPnP/1.0
15975 Realtron WebServer 1.1
15888 micro_httpd
10985 Boa/0.93.15
10364 Apache
6842 Microsoft-IIS/7.5
6691 Microsoft-IIS/6.0
```

Searching for http servers with "Server: RomPager" header:

```
$ grep RomPager index.txt | cut -d\; -f1 > ips-rompager.txt 
```

IP country Geolocalization:

```
$ xargs -n1 -I% sh -c 'echo -n %";"; geoiplookup %' < ips-rompager.txt | sed -n 's/GeoIP Country Edition: //p' | tee ips-rompager-country.txt 

...
109.80.102.50;CZ, Czech Republic
109.80.107.72;CZ, Czech Republic
109.80.11.114;CZ, Czech Republic
...
```

Count by country:

```
$ awk -F';' '{ x[$2]++ } END { for(k in x) print x[k], k; }' < ips-rompager-country.txt | sort -nr 

172155 CO, Colombia
35670 PE, Peru
11221 AR, Argentina
8724 CZ, Czech Republic
2021 DE, Germany
330 BR, Brazil
49 GB, United Kingdom
```

With the SAVE_GET option: 

```
$ gcc tsc.c -o tsc -lpthread -DSAVE_GET
```

It also creates a hierarchical directory structure with the output of execution:

```
http://192.168.0.1/index.html -> ./out/192/168/0/1:80. 
```

##### Explotacion extructura "out/" 

We can also use the directory structure to search by content in the html pages, for example, "mycorp" appears on the server home page:

```
$ grep -r -i mycorp --colour -H -m 1 out

...
out/213/0/43/68:80: <li><a href="http://www.mycorp.com/on/io/navegacion/on.html?servicio=entrada&entrada=aviso_legal_home" TARGET="_BLANK">Aviso legal</a></li>
out/223/197/87/54:80: <meta name="keywords" content="mycorp, clients"/>
out/223/14/216/32:80: <meta http-equiv="refresh" content="0;URL=http://m2m.mycorp.com/psc">
...
```

These searches are usually slow due to the volume of files, we can try to optimize by parallelizing. Example: 10 "grep" tasks that search each one in 1000 files:

```
$ find out -type f -name *:80 -print0 | xargs -0 -P 10 -n 1000 grep -i mycorp --colour -H   
```

Furthermore, the file structure takes up quite a bit (approx. 4gb). We can optimize it by compressing the result in a single file:

```
$ tar cvfz all-80.tar.gz out 
```

And do the searches directly on the compressed file:

```
$ tar xfz all-80.tar.gz --to-command 'grep --label=$TAR_FILENAME -H --colour -m 1 mycorp; true'  
```

Again, it is a slow process; Since almost all the content is text, we can optimize it a lot ... two examples, using "awk" or "sed":

```
$ gzip -dc all-80.tar.gz | egrep -e '^out.*:80' -e 'mycorp' | awk '{ if (match($0, "^out")) x = $0; else print x, $0 }'
$ gzip -dc all-80.tar.gz | egrep -e '^out.*:80' -e 'mycorp' | sed -n '/^out/{ N; s/\n/;/; /;out/ !P }' 
```

One last example: we are going to calculate the distribution by country of vulnerable ZTE routers, for this we will look for the text string "ZXV10 W300" in the html page returned by the router:

```
$ gzip -dc all-80.tar.gz | egrep -e '^out.*:80' -ie 'ZXV10 W300' | sed -n -e '/^out/{ N; s/\n/;/; /;out/ !P }' > found-zte.txt 
$ sed -e 's:out/::' -e 's:/:.:g' found-zte.out | awk -F';' '{ print $1 }' | sort -u > ips-zte.out 
$ xargs -I% sh -c 'echo -n %";"; geoiplookup %' < ips-zte.out | sed -n 's/GeoIP Country Edition: //p' > ips-zte-country.txt
$ awk -F';' '{ x[$2]++ } END { for(k in x) print x[k], k; }' < ips-zte-country.txt | sort -nr 

85499 CO, Colombia
748 AR, Argentina
10 CL, Chile
```

## Authors

* **José Ignacio Bravo** - *Initial work* - nacho.bravo@gmail.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

