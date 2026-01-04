+++
title = "Let's Learn LLL! Part 2"
date = "2025-11-17T14:10:12+08:00"
author = "azazo"
description = "when you have lll everything looks like a lattice reduction problem"
tags = ["ctf", "lattice"]
showFullContent = false
readingTime = false
hideComments = false
draft = true
+++

*This is part 2 of a series about LLL. You can read part 1 [here](https://blog.azazo.me/posts/lattice-1/).*

# Introduction
Last time, we discussed what lattices are, and looked at an algorithm to solve lattice reduction problems. As a refresher, lattices are linear combinations of vectors with integer coefficients, and lattice reduction algorithms take in a basis for a lattice and returns another basis with hopefully shorter basis vectors. LLL is a very common lattice reduction algorithm that gives us a bound on what the length of the shortest vector in the basis it returns is.

