+++
title = "Divisibility state machines, combinatorial circuits, and regexs"
date = "2025-10-26T23:54:12+08:00"
author = "azazo"
description = "Another filler post"
showFullContent = false
readingTime = false
hideComments = false
draft = true
+++

{{< math >}}

# Introduction
My friend cane recently posted about [a combinatorial circuit that yields primes](https://canairo.github.io/2025/10/19/fun-with-gates.html) (very cool go read it first). Aside from making me remember CS2100 trauma, it also reminded me that testing for divisibility (calculating remainders, in fact) can be represented as a finite state machine, so let's do that.

# Finite state machines
A finite state machine (FSM) is, informally, a collection of states and transitions between those states. The FSM takes in a string (or rather a sequence of symbols), and traverses between the states, and accepts or rejects the input based on the final state.

FSMs can be represented by directed graphs. Here is an example from Wikipedia, which coincidentally happens to be a FSM that determines whether a binary string is a number divisible by 3.

image here

There are three states -- \(S_0\), \(S_1\), \(S_2\) -- represented by verticies in the graph. the arrows represent transitions between states, with the label showing which symbol the transition takes. The "empty" arrow pointing to \(S_0\) indicates that it is the starting state, and the double circle on \(S_0\) indicates that it is an accept state. The string `10010` would traverse through the graph in the order \(S_0 \rightarrow S_1 \rightarrow S_2 \rightarrow S_1 \rightarrow S_0 \rightarrow S_0\), ending in an accept state, so the number `0b10010 = 18` is a multiple of 3.

# Finding remainders
You might have noticed that there are three states in a FSM for divisibility by 3. This is not a coincidence! In fact, the three states represent the remainder when dividing by 3. The transitions then can be easily understood: every time you accept a new bit, you are multiplying the current number by 2 then adding either 0 or 1, so we can figure out which arrow goes where with modular arithmetic.

# Turning FSMs into combinatorial circuits

# Turning FSMs into regexs