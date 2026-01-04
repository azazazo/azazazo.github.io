+++
title = "Attention is all you need"
date = "2025-09-11T18:06:12+08:00"
author = "azazo"
description = "only NINETY NINE percent of ATTENTIVE readers can spot this INGENIOUS argument"
tags = ["math"]
showFullContent = false
readingTime = false
hideComments = false
draft = true
+++

{{< math >}}

# Introduction
Abel once said that Gauss "is like the fox, who effaces his tracks in the sand with his tail", to which Gauss replied, "no self-respecting architect leaves the scaffolding in place after completing his building". Indeed, Gauss's motto was "Pauca sed Matura" (few but ripe), and his work was often terse and opaque, devoid of motivation.

Like Gauss, some modern math proofs don't really show their author's reasoning, but rather presents a clean and polished result with details swept away. However, sometimes the thought process behind the proof is also rather interesting. In this post, I will introduce 3 "miraculous" proofs, and try to break down the thought process behind them.

# Sum of rational cubes

> **Claim**: Every rational number can be expressed as the sum of three cubes of rational numbers.
> 
> **Proof**:
> Notice that
> \[
x = \left(\frac{-x^3 + 243x - 729}{9x^2 - 81x + 729}\right)^3 + \left(\frac{-3x^2 + 27x}{x^2 - 9x + 81}\right)^3 + \left(\frac{x+9}{9}\right)^3
\]
> Hence proven.

What a brilliant proof that pulls values out of nowhere. So, how can we construct three rational functions that when cubed, sum up to a desired value? Let's say that we have two polynomials \(f(x)\) and \(g(x)\). If we consider the sum of their cubes, we can see that
\[
    f^3 + g^3 = (f + g)(f^2 - fg + g^2)
\]
Now, if the second term on the right _just so happens_ to be a perfect cube (let's say \(p^3\)), we can divide by it on both sides to get
\[
    \left(\frac{f}{p}\right)^3 + \left(\frac{g}{p}\right)^3 = (f + g)
\]
Again, if \(f+g\) _just so happens_ to be the sum of a cube \(q^3\) plus a constant multiple of \(x\), we can write
\[
    \left(\frac{f}{p}\right)^3 + \left(\frac{g}{p}\right)^3 - q^3 = kx
\]
If we then substitute \(x = \frac a k\) into the above expression, we will have successfully expressed \(a\) in terms of cubes of rational functions of \(a\), which in turn are rational. We have now reduced(?) the problem of finding polyonmials \(f, g\) such that
\[
    \begin{align}
    f^2 - fg + g^2 &= p^3\\
    f + g &= q^3 + kx
    \end{align}
\]
where \(p, q\) are also polynomials and \(k\) is a constant.

Now, we consider factorising \(f^3 + g^3\) another way by bringing in a cube root of unity \(\omega = e^{i\pi/6}\):
\[
    f^3 + g^3 = (f + g)(f + \omega g)(f + \omega^2 g)
\]
so
\[
    p^3 = (f + \omega g)(f + \omega^2 g)
\]
and since the two terms on the right are conjugates, it suffices to find \(f, g\) such that \(f + \omega g\) is a perfect cube, \(u^3\). And since \(\omega + \omega^2 = -1\),
\[
    \begin{align}
    f + g &= - (\omega f + \omega^2 g + \omega^2 f + \omega g)\\
    &= - (\omega u^3 + \omega^2 \bar{u}^3 )\\
    &= q^3 + kx
    \end{align}
\]
So, we have now further reduced the problem to finding a polynomial \(u\) such that \(- (\omega u^3 + \omega^2 \bar{u}^3 )\) is a perfect cube plus a constant multiple of \(x\). If we let \(u\) be a monic linear polynomial, say \(u(x) = x + z\), we find that
\[
    \begin{align}
    - (\omega u^3 + \omega^2 \bar{u}^3 ) &= - (\omega (x + z)^3 + \omega^2 (x + \bar{z})^3 )\\
    &= - (\omega (x^3 + 3zx^2 + 3z^2x + z^3) + \omega^2 (x^3 + 3\bar{z}x^2 + 3\bar{z}^2x + \bar{z}^3) )\\
    &= x^3 - 3(\omega z + \omega^2\bar{z})x^2 + 3(\omega z^2 + \omega^2\bar{z}^2)x + z^3 + \bar{z}^3
    \end{align}
\]
and if we take \(z = -\omega\),
\[
    \begin{align}
    - (\omega u^3 + \omega^2 \bar{u}^3 ) &= x^3 - 3x^2 - 6x - 1\\
    &= (x - 1)^3 - 9x
    \end{align}
\]
so
\[
    \begin{align}
    u &= x - \omega\\
    p &= u\bar{u}\\
    &= x^2 + x + 1\\
    q &= x - 1\\
    k &= -9\\
    f &= \frac{\omega u^3 - \bar{u}^3}{\omega - 1}\\
    &= x^3 - 3x - 1\\
    g &= \frac{u^3 - \bar{u}^3}{\omega - \omega^2}\\
    &= -3x^2 - 3x
    \end{align}
\]
and putting everything together,
\[
    \left(\frac{x^3 - 3x - 1}{x^2 + x + 1}\right)^3 + \left(\frac{-3x^2 - 3x}{x^2 + x + 1}\right)^3 - (x-1)^3 = -9x
\]

Finally, substituting \(x = -\frac a 9\), we get
\[
    \left(\frac{-a^3 + 243a - 729}{9a^2 - 81a + 729}\right)^3 + \left(\frac{-3a^2 + 27a}{a^2 - 9a + 81}\right)^3 + \left(\frac{a+9}{9}\right)^3 = a
\]

Hence proven.

# Prime sum of two squares

> **Claim**: Every prime number \(p\) that is \(1 \bmod 4\) is the sum of two squares.
>
> **Proof**: Consider the finite set \(S = \{(x, y, z) \in \mathbb{N}^3: x^2 + 4yz = p\}\), and an involution defined by
> \[
(x, y, z) \mapsto \left\{\begin{array}{ll}
        (x+2z, z, y-x-z) & \text{if } x < y-z\\
        (2y-x, y, x-y+z) & \text{if } y-z < x < 2y\\
        (x-2y, x-y+z, y) & \text{if } 2y < x
        \end{array}\right.
\]
> Note that involution has exactly one fixed point, so \(\left|S\right|\) is odd and the involution \((x,y,z) \mapsto (x,z,y)\) must also have a fixed point. Hence proven.

This is a rather famous "one-sentence" proof. There are many other ways of proving the claim, including [another non-constructive proof using lattices](https://blog.azazo.me/posts/lattice-1/#tangent-fermats-theorem-no-not-that-one).

First, let's fill in the tiny gap in the proof. If \((x,y,z) \mapsto (x,z,y)\) has a fixed point, say \((a,b,b)\), then \(p = a^2 + 4b^2 = a^2 + (2b)^2\) as desired. So we just need to show that the cardinality of \(S\) is odd. We can do this by constructing another involution with only one fixed point that is known, say, the trivial solution of \((1, 1, k)\) where \(p = 4k+1\).

If we represent this new involution by 
\[
    \begin{align}
    (x, y, z) \mapsto (&m_{11}x + m_{12}y + m_{13}z,\\
    &m_{21}x + m_{22}y + m_{23}z,\\
    &m_{31}x + m_{32}y + m_{33}z)
    \end{align}
\]
our chosen fixed point of \((1,1,k)\) demands that
\[
    \begin{align}
    m_{11} + m_{12} + m_{13}k &= 1\\
    m_{21} + m_{22} + m_{23}k &= 1\\
    m_{31} + m_{32} + m_{33}k &= k\\
    \end{align}
\]
which must hold for every \(k\), so \(m_{13} = 0, m_{23} = 0, m_{33} = 1\) and
\[
    \begin{align}
    m_{11} + m_{12} &= 1\\
    m_{21} + m_{22} &= 1\\
    m_{31} + m_{32} &= 0\\
    \end{align}
\]
Furthermore, we have that
\[
    \begin{align}
    x^2 + 4yz &= (m_{11}x + m_{12}y + m_{13}z)^2 + 4(m_{21}x + m_{22}y + m_{23}z)(m_{31}x + m_{32}y + m_{33}z)\\
    &= (m_{11}x + m_{12}y)^2 + 4(m_{21}x + m_{22}y)(m_{31}x + m_{32}y + z)\\
    &= (m_{11}^2 + 4m_{21}m_{31})x^2 + (m_{12}^2 + 4m_{22}m_{32})y^2 + (2m_{11}m_{12} + 4m_{21}m_{32} + 4m_{22}m_{31})xy + 4m_{21}xz + 4m_{22}yz
    \end{align}
\]
and by comparing coefficients we can further get
\[
    \begin{align}
    m_{11}^2 + 4m_{21}m_{31} = 1\\
    m_{12}^2 + 4m_{22}m_{32} = 0\\
    2m_{11}m_{12} + 4m_{21}m_{32} + 4m_{22}m_{31} = 0\\
    m_{21} = 0\\
    m_{22} = 1\\
    \end{align}
\]
So \(m_{11}^2 = 1\). If we take \(m_{11} = 1\), we get the identity that fixes every point, which is not what we want. Therefore, we take \(m_{11} = -1\), and the complete map is given by
\[
    (x, y, z) \mapsto (-x + 2y, y, x - y + z)
\]
Curiously, this map is an involution despite the fact that we didn't require it to be one when deriving it. However, if \(-x + 2y\) or \(x - y + z\) are not positive, then we are in trouble. However, we can use two other involutions to aid us: the previously discussed flipping involution \((x,y,z) \mapsto (x,z,y)\) and the new negation involution \((x,y,z) \mapsto (-x,y,z)\).

First, note that \(-x + 2y\) and \(x - y + z\) cannot both be not positive, so we can consider the cases separately. If \(-x + 2y <= 0\) TODO

# Approximations for pi

> **Claim**: \(\pi < \frac{22}{7}\).
> 
> **Proof**: \(0 < \int_0^1 \frac{x^4(1-x)^4}{1+x^2} \, dx = \frac{22}{7} - \pi\).

This is another famous short proof, devised by an electrical engineer, Donald Percy Dalzell in 1944. As shown by Archimedes, this result can also be proved by calculating the perimeter of a 96-sided regular polygon, but as you can see, this is a much more clean (and perhaps simpler) proof. Again, there are a lot of steps missing from this proof, namely both the inequality and the equality. The inequality can be proved by observing that the integrand is non-negative for all real numbers from \(0\) to \(1\), and not zero for a value of \(x \in (0, 1)\). The integral itself can be evaluated normally:

\[
    \begin{align}
    \int_0^1 \frac{x^4(1-x)^4}{1+x^2} \, dx &= \int_0^1 \frac{x^8 - 4x^7 + 6x^6 - 4x^5 + x^4}{1+x^2} \, dx\\
    &= \int_0^1 x^6 - 4x^5 + 5x^4 - 4x^2 + 4 - \frac{4}{1+x^2} \, dx\\
    &= \left.\left( \frac{x^7}{7} - \frac{2x^6}{3} + x^5 - \frac{4x^3}{3} + 4x - 4\arctan x \right)\right|_0^1\\
    &= \frac{22}{7} - \pi\\
    \end{align}
\]

It is a well known fact that \(4\int_0^1 (1+x^2)^{-1} \, dx = \pi\), and this proof cleverly uses this. In fact, if we let \(P(x)\) be any polynomial in \(\mathbb{Q}[x]\), we have
\[
    \begin{align}
    \int_0^1 \frac{P(x)}{1+x^2} \, dx &= \int_0^1 Q(x) + \frac{R(x)}{1+x^2} \, dx\\
    &= \int_0^1 Q(x) + \frac{2mx}{1+x^2} + \frac{n}{1+x^2} \, dx\\
    &= \int_0^1 Q(x) \, dx + m \ln 2 + \frac{n}{4} \pi
    \end{align}
\]
with \(P(x) = (1+x^2)Q(x) + R(x)\), \(Q, R \in \mathbb{Q}[x]\), \(\deg R < 2\), and \(R(x) = 2mx + n\), \(m, n \in \mathbb{Q}\). Since \(Q \in \mathbb{Q}[x]\), \(\int_0^1 Q(x) \, dx \in \mathbb{Q}\), and we can always choose an appropriate \(P(x)\) to force \(m = 0\) (and \(n = - 4\) if we're particular about that too). 

However, not all polynomials make good choices for \(P(x)\); if we choose \(P(x) = 10x^2 + 6\) then we still get that \(\pi < 10\), but that's not very useful. Ideally we want \(P(x)\) to be very _very_ small (and even zero) over the range for integration. Since \(0 \le x^4(1-x)^4 \le 4^{-4}\), it is a relatively good choice to pick for \(P(x)\), and just so happens to yield the \(\frac{22}7\) approximation.

Naturally, we can generalise the current numerator into \(P(x) = x^m(1-x)^n\) with \(m, n \in \mathbb{Z}\) and investigate the approximations we get from them. Set
\[
    x^m(1-x)^n = (1+x^2)Q(x) + ax + b
\]
and since we want \(a = 0\) to kill the \(\ln 2\) term, we can substitute \(x = i\) and \(x = -i\) to get
\[
    \begin{align}
    a &= \frac12 \left(i^m(1-i)^n - (-i)^m(1+i)^n\right)\\
    b &= \frac1{2i} \left(i^m(1-i)^n + (-i)^m(1+i)^n\right)
    \end{align}
\]

The two terms inside the brackets are complex conjugates, so for \(a = 0\) we want \(i^m(1-i)^n \in \mathbb{R}\), implying that
\[
    m\left(\frac\pi 2\right) + n(-\frac\pi 4) = k\pi, k \in \mathbb{Z}
\]
or, equivalently,
\[
    2m \equiv n \pmod{4}
\]
and the approximation for \(\pi\) that is yielded becomes more precise with larger \(m\) and \(n\).

