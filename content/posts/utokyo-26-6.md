+++
title = "About problem 6 from Tokyo University's math entrance exam"
date = "2026-06-15T22:40:00+08:00"
author = "azazo"
description = "a short filler post"
tags = ["math"]
showFullContent = false
readingTime = false
hideComments = false
+++

{{< math >}}

Long time no see. Due to several real-life commitments I haven't been posting much (or be active in CTFs, though there's some more reasons behind that), but I do have some posts still in the drafts. This is a relatively short post because I want to try writing things that are on a smaller scale and easier to typeset so I can finish them faster.

# the problem

The following problem is the 6th problem in Tokyo University's math entrance exam for STEM this year, and was making the rounds on social media due to it being slightly more difficult than usual years. The problem has been translated into English by me.

> Let \(n\) be a positive integer. Let \(f(n)\) and \(g(n)\) denote the number of positive factors of \(n\) that leave a remainder of 1 and 2 when divided by 3 respectively.
> (1) Find the values of \(f(2800)\) and \(g(2800)\).
> (2) Prove that \(f(n) \ge g(n)\).
> (3) Find all possible values of \(f(n)\) when \(g(n) = 15\).

# my solution

Throughout this solution, let \(n\) be a positive integer. First, note that \[
    \begin{align}
    f(3n) &= f(n)\\
    g(3n) &= g(n)
    \end{align}
\]
so we effectively only need to consider \(n\)s not divisible by 3.

From the fundamental theorem of arithmetic we can uniquely factor \(n\) as \[
    n = \prod p_i^{d_i} \cdot \prod q_i^{e_i}
\]
where \(p_i\) are primes that are \(1 \pmod 3\) and \(q_i\) are primes that are \(2 \pmod 3\). It is well known that the total number of factors of \(n = f(n) + g(n)\) can be expressed as \(\prod (d_i+1) \cdot \prod (e_i+1)\): every factor is obtained by choosing a number of prime factors to multiply together, and there are \(e_1+1\) different choices for the number of \(p_1\)s, \(e_2+1\) different choices for the number of \(p_2\)s, and so on.

For \(n \equiv 2 \pmod 3\), it can be shown that \(f(n) = g(n)\): for a factor \(x\) of \(n\), if \(x \equiv 1 \pmod 3\) then \(n/x \equiv 2 \pmod 3\) and vice versa, so there is a bijection between the factors that are \(1 \pmod 3\) and \(2 \pmod 3\). Therefore, for \(n \equiv 2 \pmod 3\), \[
    f(n) = g(n) = \frac12\prod\left(d_i+1\right)\prod\left(e_i+1\right)
\]

We will now focus our attention to the remainders of the factors upon division by 3. Since multiplying by a \(p_i\) does not change the remainder of a factor, we only need to think about the \(q_i\)s. An even number of \(q_i\)s multiplied together has remainder \(1 \bmod 3\), so we can rephrase our inquiry as:
> Given some positive integers \(e_i\), how many ways are there to pick integers \(a_i\) between \(0\) and \(e_i\) inclusive such that \(\sum a_i\) is even?

If not all \(e_i\) are even, then out of all the possible sums exactly half are even. To see this, rearrange the \(e_i\)s such that \(e_1\) is odd. The final sum will be even if \(\sum_{i > 1} a_i\) and \(a_1\) are both odd or are both even. Either way, since \(e_1\) is odd, half of the choices for \(a_1\) will be odd and the other half will be even, so half of the total possible sums are even. In this case, there are \(\frac12\prod\left(e_i+1\right)\) possible even sums, so \[
    f(n) = g(n) = \frac12\prod\left(d_i+1\right)\prod\left(e_i+1\right)
\] which is identical to when \(n \equiv 2 \pmod 3\).

In the case that all \(e_i\) are even, for most choices of \(e_i\)s that result in an even sum we can associate it to a choice of \(e_i\)s that has odd sum. For a choice of \(a_i\) we associate it with the set \(A_k\), where \(k\) is the smallest integer such that \(a_k\) is non-zero. Within each set \(A_k\), we can use the same reasoning as above to conclude that there is an equal number of choices with odd sum and choices with even sum in every \(A_i\). The only choice that is not included in any \(A_i\) is when all \(a_i\) are 0, so we get that there is exactly 1 more choice that result in even sum than the choices that result in odd sum. Therefore, \[
    \begin{align}
    f(n) &= \frac12\prod\left(d_i+1\right)\left(\prod\left(e_i+1\right)+1\right)\\
    g(n) &= \frac12\prod\left(d_i+1\right)\left(\prod\left(e_i+1\right)-1\right)\\
    \end{align}
\]

That was a lot of work, but we can now answer the question easily.
1. Since \(2800 = 2^4 \cdot 5^2 \cdot 7\), \[
    \begin{align}
    f(2800) &= \frac12\left(2\right)\left(5 \cdot 3 + 1\right)\\
    &= 16\\
    \\
    g(2800) &= \frac12\left(2\right)\left(5 \cdot 3 - 1\right)\\
    &= 14\\
    \end{align}
\]
1. Follows trivially from the formulas we have derived.
2. One possible value of \(f(n)\) is \(g(n) = 15\). For the other possible values, see that \[
    \begin{align}
    f(n) - g(n) &= \frac12\prod\left(d_i+1\right)\left(\prod\left(e_i+1\right)+1\right) - \frac12\prod\left(d_i+1\right)\left(\prod\left(e_i+1\right)-1\right)\\
    &= \prod\left(d_i+1\right)
    \end{align}
\]
We know that \(\prod\left(d_i+1\right)\left(\prod\left(e_i+1\right)-1\right) = 30\) and that \(\left(\prod\left(e_i+1\right)-1\right)\) must be even, so the possible values for \(\prod\left(d_i+1\right)\) are the factors of 15 which are \(1, 3, 5, 15\), leading to the possible values of \(16, 18, 20, 30\) for \(f(n)\). Combining all values, we have that \(f(n) \in \left\{15, 16, 18, 20, 30\right\}\).

# thoughts

This is honestly not that hard of a question. For a typical test-taker, given the limited time the optimal way may just to bash out the solutions for parts 1 and 3, and prove 2 by something like induction (\(n \equiv 2 \pmod 3\) as base case and consider what happens when multiplying a prime that has remainder \(2 \bmod 3\)). However, this question's difficulty is just right in the sense that if you spend just a little bit more time thinking you can arrive at a very neat solution. As such, I feel that this question is rather suitable to serve as a "litmus test" to judge people's opinions on math: would you take the shortest albeit inelegant path possible to the solution, or would you take a longer but more scenic route?

I do quite like my solution to this problem, especially because the formulas for \(f(n)\) and \(g(n)\) were derived in a very nice manner; the key lemma(?) on counting even sums of \(a_i\) is proved in a very cute way. That being said, I had maybe about a whole free day in camp to refine a rough initial solution I thought of in 20 minutes, so maybe if I were an aspiring student my final solution wouldn't be so nice (if I had enough time to finish it at all).

That's it for today. I wrote this entire post in one night so there may be some errors; apologies in advance. See you soon!