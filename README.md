# DNS in a Weekend

This repository contains my implementation of Julia Evans' tutorial [DNS in a Weekend](https://implement-dns.wizardzines.com).
The tutorial gives example code in Python but I wanted more challenge and an opportunity to practice writing in Go so I've written this implementation in Go.

The goal of the project is to implement a toy DNS resolver and to learn a bit about how DNS works in the process.

## Scope and Limitations

Currently this project implements the resolver that is described in the main tutorial, which is a bare bones DNS resolver.
The current implementation sends a query directly to a root nameserver and follows the additionals and authorities sections in the response to eventually get an answer containing the IP address associated with the given domain name.
The currently implementation only handles type A and NS records.
It does not implement any caching, concurrency, or security hardening.

## Learning

This project has been a fantastic learning experience for me!

I feel much more comfortable using Go now.
Translating the provided Python code helped me map concepts and thought processes that I am very comfortable with in Python, into Go.
In addition, I tried applying some advice that I was given years ago by my former mentor at Blackberry, to use the language spec to better learn the language.
At the time I very much under appreciated this advice but applying it during this project really helped me clarify how certain language elements relate to each other. For example, I finally made the connection that the syntax to declare a named struct is actually two language concepts being used together.

For example, the line `type DNSHeader struct{}` contains a type declaration (`type DNSHeader`) and a struct declaration (`struct {}`).

I also exercised some basic decision making skills that I had allowed to stagnate.
For instance, I initially split my code into two files, `query.go` and `response.go` on the basis of how the tutorial progresses.
By the end of part 2 it was clear to me that related concepts were now split between the two files, so I decided to combine both into a single file.
As a general principal, I think it makes sense to defer a decision to split up code until it become clear that a decision is actually necessary.
At that time, there will hopefully be enough information to inform the decision.
The mistake I made was anticipating future needs without any clear indication of what those needs would actually be.

## Future Work

I plan to return to this project to keep developing it.
There are exercises at the end of the tutorial to guide this work, but I plan to attempt the following:
1. Benchmark current performance
1. Implement caching
1. Disallow loops in DNS compression
1. Add support for more record types
1. Turn the resolver into a server
1. Configure my system to use my resolver and see what breaks

## Use of AI

I limited my use of AI to assisting in research to maximize learning.
