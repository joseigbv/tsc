# tsc
Simple dependency free tcp scan tool for UNIX/Linux and MS Windows

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

The tsc scanner should run on any UNIX/Linux or Win32 box. You only need a relatively modern gcc compiler. To compile for another architecture (eg Solaris SPARC) you will need a cross compiler. 
There are two versions: single or with threads.

### Installing

Download a copy of the project from github: 

```
git clone https://github.com/joseigbv/tsc
```

Edit 'tsc.c' and change configuration (optional).

Compile.

* linux: 
```
gcc -Wall -O2 tsc.c -o tsc -lpthread
```
* osx: 
```
gcc -Wall -O2 tsc.c -o tsc
```
* win32 (mingw): 
```
gcc -Wall -O2 tsc.c -o tsc -lwsock32
```
* solaris: 
```
gcc -Wall -O2 tsc.c -o tsc -lsocket -lnsl
```

### Usage 

Pending ...

## Authors

* **José Ignacio Bravo** - *Initial work* - nacho.bravo@gmail.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

