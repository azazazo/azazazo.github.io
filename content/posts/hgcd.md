+++
title = "The Half-GCD algorithm"
date = "2024-11-04T18:06:12+08:00"
author = "azazo"
description = "divide and conquer goes brrrrr"
tags = ["math", "ctf"]
showFullContent = false
readingTime = false
hideComments = false
draft = true
+++

{{< math >}}

# introduction
The greatest common divisor of two numbers \(a\) and \(b\) is the greatest positive integer \(d\) such that \(d\) is a divisor of both \(a\) and \(b\). For example, the GCD of \(12\) and \(56\) is \(4\): the factors of \(12\) are \(1, 2, 3, 4, 6, 12\) and the factors of \(56\) are \(1, 2, 4, 7, 8, 14, 28, 56\), so taking the greatest number that is a factor of both yields the GCD.

There are many different ways to calculate the GCD of two numbers. One way is what we did just now: finding the set of factors for both numbers, then finding the greatest number that is in both sets. However, [integer factorisation is hard](https://en.wikipedia.org/wiki/Integer_factorization). The algorithms with best theoretical time complexities are only subexponential, and it's widely believed that no algorithm can factor all integers in polynomial time.

You might have realised that if \(m\) is a factor of \(a\) and \(b\), then it is also a factor of \(a - b\), and so we can repeatedly subtract the smaller number from the bigger until further subtraction would result in a negative integer, then repeat this process until one of the numbers is zero. The other number would then be the GCD of the original two numbers.

You would not be the first to realise this. This process is termed the *Euclidean algorithm*, and is one of the oldest algorithms still commonly used today. Despite probably known before his times, the algorithm is named after Euclid who included it in Book 7 of his famous work *Elements* published around 300 BC. This algorithm was also rediscovered by Indian and Chinese mathematicians while trying to solve linear Diophantine equations, who gave it endearing names like "pulverizer" (kuṭṭaka) and "method of iterative reciprocal subtraction" (更相减损术).[^1]

A modern formulation of this algorithm (using modulo instead of repeated subtraction) would look like this:
```py
def gcd(a, b):
    if b == 0:
        return a
    else: return gcd(b, a % b)
```

How efficient is this algorithm? This question is answered by Lamé's theorem:
> The number of steps in the Euclidean algorithm when performed on \(a\) and \(b\) is less than \(5\) times the number of decimal digits of \(\min(a, b)\)

This implies that the time complexity is \(O(\log \min(a, b))\), assuming that modulos are \(O(1)\). For most use cases, this is already a very fast algorithm, but we can speed it up more by [dealing with even numbers explicitly and avoiding modulos](https://en.wikipedia.org/wiki/Binary_GCD_algorithm).

Of course, finding the GCD of two integers is very interesting and useful, but it's a bit boring. Since notions of "divisibility" also exist in algebraic structures other than the integers, one might naturally wonder: how can we extend the idea of GCD to other structures?

# introductwo
A greatest common divisor of two... "things" \(a\) and \(b\) is a thing \(d\) such that
1. \(d \vert a\) and \(d \vert b\)
2. for every thing \(g\) such that \(g \vert a\) and \(g \vert b\), \(g \vert d\) also holds

where the notation \(a \vert b\) means that "there exists a \(c\) such that \(ac = b\)".

This definition is a lot more abstract than the previous one. Instead of just using the term "greatest", we now have a more rigorous condition, and notice how the article has been changed from "the" to "a". What is going on?

For general commutative rings, there is no good way to identify the "greatest" element in a set. As an example, with the Gaussian integers \(\mathbb{Z}[i]\), \((1+i)(1-i) = 2\), so \(1+i \vert 2\) and so \(1+i\) is a GCD of \(1+i\) and \(2\). However, \(1-i\), \(-1-i\), and \(-1+i\) also satisfy the two conditions, so they are also GCDs of \(1+i\) and \(2\).[^2] So, we can't really talk about *the* GCD, unless we specifically choose one "canonical" representative element. For example, we could pick the GCD with a positive real part and nonnegative real part.

In fact, there are rings where the Euclidean algorithm fails, and rings where GCDs are not even guaranteed to exist. But continuing further down this path will lead us to A Dark Place where irreducible and prime have different meanings, things no longer factor uniquely, and "ramify" is a commonly used word, so let's not go too far. Let's stick with polynomial rings in one indeterminate over fields \(K[x]\), which behave nicely with the Euclidean algorithm.

# introducthree
The greatest common divisor of two polynomials \(F(x)\) and \(G(x)\) is the monic polynomial \(d(x)\) such that
1. \(d \vert F\) and \(d \vert G\)
2. for every polynomial \(e\) such that \(e \vert F\) and \(e \vert G\), \(e \vert d\) also holds

This is just the same definition as introduced before adapted for polynomials. We also choose the monic polynomial to be the "canonical" GCD for simplicity.

How would one implement this in, say, Sage? Since the Euclidean algorithm works in \(K[x]\), we can just do
```py
def gcd(a, b):
    if b == 0:
        return a.monic()
    else: return gcd(b, a % b)
```
which works fabulously:
```py
sage: K.<x> = GF(17)[]
sage: a = K.random_element(degree=15)
sage: b = K.random_element(degree=15)
sage: def gcd(a, b):
....:     if b == 0:
....:         return a.monic()
....:     else: return gcd(b, a % b)
....: 
sage: gcd(a, b)
1
sage: k = K.random_element(degree=3)
sage: a *= k
sage: b *= k
sage: gcd(a, b)
x^3 + 4*x^2 + 13*x + 3
sage: k.monic()
x^3 + 4*x^2 + 13*x + 3
```

Let's ponder about the time complexity of this algorithm. The total number of steps should be roughly on the order of \(O(\min(\deg F, \deg G))\), where \(\deg F\) is the degree of \(F\). At every step, we are performing a modulo. This modulo can be thought of as a division then a subtraction:

\[
    \begin{align}
    F(x) \% G(x) &= F(x) - \frac{f_{\deg F} x^{\deg F}}{g_{\deg G} x^{\deg G}} G(x)
    \end{align}
\]

Since polynomials are basically a list of numbers, this takes \(O(\min(\deg F, \deg G))\) time to compute too, so our final time complexity is something like \(O(\min(\deg F, \deg G)^2)\). Of course, this is assuming that all arithmetic operations on the coefficients of the polynomial take \(O(1)\) time. 

Quadratic time is not very good. Not necessarily unusable, but still bad enough to leave one desiring for an alternative. For example, naïve polynomial multiplication with degree \(n\) has time complexity \(O(n^2)\), but with the Fast Fourier Transform one can do it in \(O(n \log n)\) time instead. The FFT leverages divide-and-conquer by first splitting the polynomial into two polynomials, 

https://mystiz.hk/posts/2021/2021-02-15-dicectf-1/

[^1]: closely mirroring the greek term ἀνθυφαίρεσις also meaning alternating/reciprocal subtraction
[^2]: you might notice that these values differ from one another only by multiplication by \(-1\) or \(i\); \(1, -1, i, -i\) are called *units* in \(\mathbb{Z}[i]\) and the four gcds are *associates*. in particular, for integral domains, gcds must always be associates.