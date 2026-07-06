+++
title = "Anomalous elliptic curves and Smart's attack"
date = "2025-11-17T14:10:12+08:00"
author = "azazo"
description = "so smarrrrrrrrt"
tags = ["ctf", "math"]
showFullContent = false
readingTime = false
hideComments = false
draft = true
+++

{{< math >}}

# introduction

If you've dabbled in CTF cryptography before, you might know that the elliptic curve discrete logarithm problem (ECDLP) can be very easily solved if the order of the curve is equal to the prime it is defined over. This is commonly referred to as "Smart's attack" after Nigel Smart, who published a paper detailing the method, and the curves that are susceptible to this attack can be called "anomalous curves".

However, the math behind Smart's attack is slightly more involved than typical CTF math, so it's not very well understood by CTFers. I think this is a shame, because Smart's attack involves some very interesting topics that aren't often encountered. In this post I'll try to explain them as thoroughly as possible.

Heres a TLDR: the composition of maps
\[
    \widetilde{E}\left(\mathbb{F}_p\right) \xrightarrow{\text{lift}} E\left(\mathbb{Z}_p\right) \xrightarrow{\left[p\right]} E_1\left(\mathbb{Z}_p\right) \cong \mathcal{E}\left(p\mathbb{Z}_p\right) \xrightarrow{\log_{\mathcal{E}}} p\mathbb{Z}_p \xrightarrow{\bmod p^2} \mathbb{F}_p^+
\]
where
- \(\left[p\right]\) is multiplication by \(p\)
- \(E_1\left(\mathbb{Z}_p\right)\) is the group of points that reduce to the point at infinity in \(\widetilde{E}\left(\mathbb{F}_p\right)\)
- \(\mathcal{E}\left(p\mathbb{Z}_p\right)\) is the formal group for the curve \(E/\mathbb{Z}_p\)
- \(\log_{\mathcal{E}}\) is the formal logarithm

yields a homomorphism from the group of points on an anomalous curve to \(\mathbb{F}_p^+\), so the ECDLP can be translated to a DLP over \(\mathbb{F}_p^+\), which is just division.

But if you understood that you probably don't need this post anyways, so let's just get started.

# \(p\)-adics

Before formally defining what the \(p\)-adics are, we'll try to find some intuition for them.

Let's say that we're trying to solve the equation
\[
    x^2 + 1 = 0    
\]
Obviously, this equation has the complex roots \(i\) and \(-i\), and no roots in \(\mathbb{R}\) and thus \(\mathbb{Z}\). But what if we tried to find roots anyways?

From modular arithmetic we know that if some \(x \in \mathbb{Z}\) is a root, then it would also have to satisfy the same equation under modulo, so
\[
    x^2 + 1 \equiv 0 \pmod 5
\]
where 5 is just a small prime picked for convenience. Our equation has no roots in \(\mathbb{Z}\), but has two roots in \(\mathbb{Z}/5\mathbb{Z}\): \(x \equiv 2, 3 \pmod 5\). From this, we can say that if there were hypothetical roots in \(\mathbb{Z}\), they would have to be of the form \(5k \pm 2\). Plugging this back into our original equation, we get
\[
    \begin{align}
    \left(5k \pm 2\right)^2 + 1 &= 25k^2 \pm 20k + 5\\
    &= 0
    \end{align}
\]
Now, we can take the equation mod 25 to have
\[
    5 \pm 20k \equiv 0 \pmod{25} \Longleftrightarrow 1 \pm 4k \equiv 0 \pmod{5}
\]
which has solutions \(k \equiv 1, 4 \pmod{5}\) in the plus and minus cases respectively.

From this we can improve on our hypothetical roots and say that they are of the form \(25k \pm 7\), substitute again, giving us \(625k^2 \pm 350k + 50 = 0\). We can take mod 125 on this equation, which results in
\[
    50 \pm 350k \equiv 0 \pmod{125} \Longleftrightarrow 2 \pm 4k \equiv 0 \pmod{5}
\]
with solutions \(k \equiv 2, 3 \pmod{5}\). This let us improve our roots to be \(125k \pm 57\).

We can continue this process forever to get a root of the equation \(x^2 + 1 = 0\) that is "in" \(\mathbb{Z}\): it looks something like
\[
    2 + 1 \cdot 5 + 2 \cdot 5^2 + 1 \cdot 5^3 + 2 \cdot 5^4 + \dots
\]
Of course, this does not converge to a sensible value in \(\mathbb{Z}\), but it *is* a solution to the equation in some sense. The idea behind \(p\)-adic numbers is to construct an algebraic structure where this infinite sum makes sense and actually converges to a value.

To see how we can do that, we will need to start formally defining the \(p\)-adic numbers. Let \(p\) be a prime number, and define the \(p\)-adic valuation of a rational number \(x\), \(v_p(x)\), to be the largest integer \(k\) such that \(x\) can be written as \(p^k \frac r s\) where both \(r\) and \(s\) are indivisible by \(p\). We also set \(v_p(0) = \infty\).

We can then define a \(p\)-adic absolute value as an analogue to the normal absolute value, \(\left|\cdot\right|_p\), that takes in a rational number \(x\) and returns \(p^{-v_p\left(x\right)}\). The *field of \(p\)-adic numbers*, denoted as \(\mathbb{Q}_p\), is then the completion of \(\mathbb{Q}\) with respect to \(\left|\cdot\right|_p\).

What does this mean? We can look to the field of real numbers \(\mathbb{R}\) for an analogy. One way of constructing the reals is through *Cauchy sequences*, which are sequences \(\left(x_1, x_2, x_3, \dots\right)\) such that for every rational number \(\varepsilon > 0\), there exists a positive integer \(N\) such that for all \(m, n \ge N\) one has that \(\left|x_m - x_n\right| < \varepsilon\) (here \(\left|\cdot\right|\) denotes the normal absolute value). For example, some Cauchy sequences are \((3, 3.14, 3.141, 3.1415, 3.14159, \dots)\) and
\[
    \begin{align}
    x_1 &= 1\\
    x_{i+1} &= \frac12 \left(x_i + \frac2{x_i}\right)
    \end{align}
\]
or \(\left(1, \frac32, \frac{17}{12}, \frac{577}{408}, \dots\right)\).

The definition is basically saying that the difference between a Cauchy seuence's terms tends to 0. Intuitively, if the terms are getting closer together, they must be getting closer to *something*, even if that something isn't in \(\mathbb{Q}\) (the second example above converges to \(\sqrt2\)). By adding all the possible values that Cauchy sequences converge to into \(\mathbb{Q}\), we *complete* it and obtain the real numbers \(\mathbb{R}\). Of course, this is an extremely oversimplified explanation, but it's the general idea behind a completion.

With the \(p\)-adic absolute value, we now have a new meaning for what it means to be "small": since \(\left|x\right|_p = p^{-v_p\left(x\right)}\), a rational \(x\) is small if it is divisible by a large power of \(p\). Consequently, two rational numbers are close whenever their difference is divisible by a large power of \(p\). This is counterintuitive to the normal absolute value, where larger powers of \(p\) are (of course) larger.

Now we are ready to look at an explicit construction of \(\mathbb{Q}_p\). We can define \(\mathbb{Q}_p\) to be the field consisting of all formal sums
\[
    \sum_{k=n}^\infty a_k p^k
\]
with \(n, a_k \in \mathbb{Z}\) and \(0 \le a_k < p\). Some examples of elements in \(\mathbb{Q}_5\) are
\[
    \begin{align}
    &2 + 1 \cdot 5\\
    &1 \cdot 5^{-1}\\
    &4 + 3 \cdot 5 + 3 \cdot 5^2 + 3 \cdot 5^3 + \dots\\
    &2 + 1 \cdot 5 + 2 \cdot 5^2 + 1 \cdot 5^3 + 2 \cdot 5^4 + \dots\\
    &1 \cdot 5^{-3} + 1 \cdot 5^{-2} + 1 \cdot 5^{-1} + 1 + 1 \cdot 5 + \dots
    \end{align}
\]

The first two examples are finite sums, while the other three are infinite. The infinite sums don't converge to anything in \(\mathbb{Q}\), but they do in \(\mathbb{Q}_p\), since the partial sums form a Cauchy sequence. Another way to think about elements of \(\mathbb{Q}_p\) is to imagine them as numbers in base-\(p\) but expansions extending infinitely to the left rather than to the right.

Arithmetic in \(\mathbb{Q}_p\) is defined in the same way as with ordinary base-\(p\) expansions. To add two elements of \(\mathbb{Q}_p\), add the coefficients of the corresponding powers of \(p\), and carry to the next power when needed. Multiplication is also performed coefficient-wise, carrying when necessary. Since there are only finitely many negative powers of \(p\) in the sum, these operations are well-defined.

As an example, we will show that the infinite sum we obtained for a root of \(x^2 + 1 = 0\) actually is a root in \(\mathbb{Q}_5\): clearly by the definition of \(\mathbb{Q}_5\) the sum is an element of the field, so we just need to check the result when we square it and add 1.
\[
    \begin{array}{rrcccccccccl}
    &(2 &+& 1\cdot5 &+& 2\cdot5^2 &+& 1\cdot5^3 &+& 2\cdot5^4 &+& \cdots)^2\\
    =& 4 &+& 2\cdot5 &+& 4\cdot5^2 &+& 2\cdot5^3 &+& 4\cdot5^4 &+& \cdots\\
     &   &+& 2\cdot5 &+& 1\cdot5^2 &+& 2\cdot5^3 &+& 1\cdot5^4 &+& \cdots\\
     &   & &         &+& 4\cdot5^2 &+& 2\cdot5^3 &+& 4\cdot5^4 &+& \cdots\\
     &   & &         & &           &+& 2\cdot5^3 &+& 1\cdot5^4 &+& \cdots\\
     &   & &         & &           & &           &+& 4\cdot5^4 &+& \cdots\\
    \\
    =& 4 &+& 4\cdot5 &+& 4\cdot5^2 &+& 4\cdot5^3 &+& 4\cdot5^4 &+& \cdots\\
    \end{array}
\]
When we add 1 to this, every single coefficient becomes 0 and carries 1 to the next power, continuing on infinitely, giving us 0. This also implies that \(-1 = 4 + 4\cdot5 + 4\cdot5^2 + \dots\) in \(\mathbb{Q}_5\); in fact the "identity" \(-1 = 1 + 2 + 4 + 8 + 16 + \dots\) holds in \(\mathbb{Q}_2\)!

Similar to how \(\mathbb{Q}\) "naturally" has \(\mathbb{Z}\) embedded in it, there is also the *ring of \(p\)-adic integers* \(\mathbb{Z}_p\) embedded within \(\mathbb{Q}_p\): \(\mathbb{Z}_p\) consists of all the \(p\)-adic numbers with valuation not smaller than 1, that is, all formal sums
\[
    \sum_{k=n}^\infty a_k p^k
\]
with \(n, a_k \in \mathbb{Z}\), \(0 \le a_k < p\), and \(n \ge 0\). Note that \(\mathbb{Z}_p\) is a ring because some elements have no inverse: \(5 \in \mathbb{Z}_5\) but clearly \(5^{-1} \notin \mathbb{Z}_5\).

# elliptic curves over \(\mathbb{Q}_p\)

Since \(\mathbb{Q}_p\) is a field, we can of course define an elliptic curve over it! As always, an elliptic curve \(E\) over \(\mathbb{Q}_p\) is defined by a Weierstrass equation
\[
    E/\mathbb{Q}_p: y^2 + a_1xy + a_3y = x^3 + a_2x^2 + a_4x + a_6
\]
where all the \(a_i\)s are in \(\mathbb{Q}_p\).

Now, since the Weierstrass equation is homogenous, we can consider making the transformation \((x, y) \mapsto (k^{-2} x', k^{-3} y')\) to obtain a new equation
\[
    E'/\mathbb{Q}_p: y'^2 + k^6a_1x'y' + k^6a_3y' = x'^3 + k^6a_2x'^2 + k^6a_4x' + k^6a_6
\]
with all the \(a_i\)s being replaced by \(k^6 a_i\). This allows us to transform the Weierstrass equation into one that yields the same curve, but with all coefficients in \(\mathbb{Z}_p\). Since the discriminant of the elliptic curve, \(\Delta\), is a polynomial in the coefficients \(a_i\), we must similarly have that \(\Delta \in \mathbb{Z}_p\) or equivalently \(v_p(\Delta) \ge 0\).

Out of all the possible choices of \(a_i \in \mathbb{Z}_p\) that yield the same curve, we can choose one that minimises the value of \(v_p(\Delta)\). The resulting Weierstrass equation is called the *minimal* Weierstrass equation, and it is unique up to a change of coordinates that does not affect \(v_p(a_i)\).

There is a natural reduction map \(\mathbb{Z}_p \rightarrow \mathbb{F}_p\) that acts "modulo \(p\)" on \(\mathbb{Z}_p\); that is,
\[
    \sum_{k=0}^\infty a_k p^k = x \mapsto \widetilde{x} = a_0
\]
In other words, reduction takes only the "constant term" of the \(p\)-adic integer. This map is commonly denoted as a tilde \(\widetilde{x}\).

We can reduce the coefficients of a minimal Weierstrass equation of \(E/\mathbb{Q}_p\) to obtain a curve over \(\mathbb{F}_p\):
\[
    \widetilde{E}/\mathbb{F}_p: y^2 + \widetilde{a}_1xy + \widetilde{a}_3y = x^3 + \widetilde{a}_2x^2 + \widetilde{a}_4x + \widetilde{a}_6
\]
Note that this new curve may be singular. We can also perform reduction on the points: for a point \(P \in E\left(\mathbb{Q}_p\right)\), we can always choose homogenous coordinates \(\left[x, y, z\right]\) such that \(x, y, z \in \mathbb{Z}_p\), and at least one of \(x\), \(y\), and \(z\) has valuation \(v_p\) equal to 0.

If we reduce the three coordinates of \(P\), we get a point \(\widetilde{P} = \left[\widetilde{x}, \widetilde{y}, \widetilde{z}\right] \in \widetilde{E}\left(\mathbb{F}_p\right)\). Just like how reducing a nonsingular curve over \(\mathbb{Q}_p\) may lead to a singular curve over \(\mathbb{F}_p\), the reduced point may be equal to the point at infinity, \(\widetilde{\mathcal{O}}\), when \(v_p(z) \ge v_p(x)\) and \(v_p(z) \ge v_p(y)\).

From here on, we assume that the reduced curve \(\widetilde{E}/\mathbb{F}_p\) is not singular. We can define a subset of \(E\left(\mathbb{Q}_p\right)\) that contains all points that reduce to the point at infinity:
\[
    E_1\left(\mathbb{Q}_p\right) = \left\{ P \in E\left(\mathbb{Q}_p\right): \widetilde{P} = \widetilde{\mathcal{O}} \right\}
\]
Clearly, \(E_1\left(\mathbb{Q}_p\right)\) is the kernel of the reduction map, so by the first isomorphism theorem we have that
\[
    \widetilde{E}\left(\mathbb{F}_p\right) \cong \frac{E\left(\mathbb{Q}_p\right)}{E_1\left(\mathbb{Q}_p\right)}
\]

# TODO: is using first isomorphism theorem here necessary? we want Ê \cong E_1

# formal groups

It's time to introduce another new algebraic structure!


# the formal group of an elliptic curve

expansion around O

# putting it altogether

go over map in intro again

# bonus: ECDLP over \(E(\mathbb{Z}/p^k \mathbb{Z})\)

# bonus: when the attack fails