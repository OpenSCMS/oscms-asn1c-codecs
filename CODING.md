# Coding and Style Conventions

Development in this repository roughly follows the Google C++
style guide (<https://google.github.io/styleguide/cppguide.html>)
modified to allow for the fact we are working primarily in C.

Code formatting is controlled by the contents of `.clang-format`
which we apply through the use of version 18 of the `clang-format`
tool.

## C Language Standard and Tooling

* The code is written to the C11 standard
* POSIX Compliance is preferred when using library functions (e.g use `stat` in preference to `access`)
* GCC Must be vesion 11 or greater
* CMake version 3.31.5 is used, being the version supported by Ubuntu 22.04

## Header Files

* Follow the guidelines under "Self-contained Headers".
* Use `#define` guard definitions in all header files, do not use the trailing underscore.
* Follow the "Include what you use" recommendations
* The Forward Declarations section is focused on C++ issues. In C, they are sometimes necessary
  * To declare an opaque type
  * To allow a `struct` to contain a pointer-to-self member.
* Inline functions should be used sparingly,
  * should not force the disclosure of internal implementation
details (such as the fields of a `struct` which could otherwise
be opaque).
  * Are always preferable to parameterized `#define` macros.
* We use a different order for include statements, whether in a header
or an implementation (.c) file.
  * System include files first, enclosed in angle-brackets
  * Intra-project files next. These would be includes from a
different component within the SDK
  * Include files located in the same component

Groups of `#include` statements should be separated by a blank line.

## Scoping

### Namespaces

In the sense of the Style Guide, these are a C++ feature and not applicabe to C.

However, related functions should be named consistently. A good convention is to
use the same initial term for all public identifiers.

Also, a prefix should be used to avoid potential clashing

### Linkage

* All internal functions for a module should be declared `static`
* Functions that may be called by other modules within the component
(e.g. a library), but not from outside, use normal external linkage.
* Functions which are intended to form the public API of a library
must be annotated with the `SO_EXPORT` qualifier in both the header file
and the implementation file.

Thus, in a module X within a library we might have

``` C
// x.h
...
#include "so_export.h"

...

void bar(); // called only by other modules in the library
SO_EXPORT void bang(); // called by library clients

--------------

// x.c

#include "X.H"

...

// Only called from within x.c
static foo() {}

void bar() {} // only called from within the library

SO_EXPORT void bang() {} // Part of the public API for the library
```

### Local variables

As per the style guide

* use the narrowest scope possible
* initialize on declaration
* avoid cryptic names

But be aware, Coverity (if you use it) may force you to move a declaration to the top of a function.

### Static Variables

In a multithreaded environment, static storage is a "Bad Idea"
and should be avoided.

The exception is for things which are write-once/read-many.

## Structs

C does not have classes, per se, though they can be emulated with
`struct`'s (indeed, that's how early C++ compilers did it).

This section largely replaces the Classes section of the style guide.

### Declarations

When declaring ta struct, the following style is strongly preferred

``` C
tyepdef {
    ... // members
} StructTypeName;
```

This allows them to be used naturally within the code body, without
constantly restating the fact that they are `structs`.

> **_NOTE:_** It is a common practice to apply the `_t` suffix to type names. We do NOT follow this. The `_t` suffix is reserved by POSIX for its own use.

### Opaque vs Exposed

Opaque types are to be preferred in a module's API whenever
that API is solely concerned with operating on objects of that
type.

An opaque type is one in which the header file contains an
incomplete (or forward) declaration, and the full declaration
is only available within the body file.

``` C
// X.h

typedef struct implementation implementation;

implementation * implementation_new();
void do_something_with(implementation *thing);
void implementation_free(implementation *thing);

////////////////

// X.c

#include "X.h"

// The typedef is in the header file, so we do not repeat it here.

struct implementation {
    ...
};

...
```

The best example, from the earliest days of C, is the `FILE` structure
used in all of the file-i/o standard library functions. If you dig into
the header files for your compiler, you will never find a `struct`
body delcaration for `FILE`. Only those functions know what is inside
a `FILE` structure, so it can change between operating systems or
even compiler versions without breaking any code.

However, this approach necessitates dynamic memory management by the client -
including the need for `new` and `delete` functions in the API.

The alternative is to expose the internal details of the `struct` within
the header file. This allows clients to declare arrays of these objects
and obviates the need to manage memory manually.

Whichever approach is used, functions must never either accept a
structure as an argument, or return one as the function value.

Always pass and return pointers.

## Naming

The following terms are used to describe different case forms:

* snake-case: All lower case, with words separated by underscores, E.g. snake_case_name
* UPPER-SNAKE-CASE: Like snake case, but all letters are upper case. E.g. UPPER_SNAKE_CASE_NAME
* camel-case: First word is all lower case, remaining words begin with an upper case letter. E.g. camelCaseName
* Pascal-case: Like camel-case except the first letter is also upper case. E.g. PascalCaseName

In general, the following naming conventions must be followed:

* (source) file names: snake-case, no spaces.
* `typedef`s, `struct`s, and `enum` types: Pascal-case
* `#define` constants and `enum` type members: UPPER-SNAKE-CASE
* functions: snake-case
* variables: snake-case
