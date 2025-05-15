+++
title = "Evaluating sums with the residue theorem"
date = "2025-05-15T11:41:30+08:00"
author = "azazo"
description = "A (perhaps surprising) application"
showFullContent = false
readingTime = false
hideComments = false
+++

{{< math >}}

The residue theorem (or Cauchy's residue theorem) is an incredibly powerful tool that can aid in evaluating integrals of analytic functions over closed curves.

> **Theorem**: Let \(f(z)\) be a meromorphic function; that is, \(f\) is analytic except at a finite list of singularities, then
> \[
    \oint_{C} f(z) dz = 2\pi i\sum \text{Res}(f, a)
\]
> where \(\text{Res}(f, a)\) represents the residue of \(f\) at \(a\), and \(a\) runs over every singularity contained within the curve \(C\) in the sum.

By equating an integral to a finite sum, the residue theorem can be used to solve many seemingly hard integrals.

> **Example**: Find the value of \(\int_{-\infty}^{\infty} \frac{\cos(x)}{1+x^2} dx\).\
> We define the function \(f(z) = \frac{e^{iz}}{1+z^2}\). Clearly the desired integral is equal to \(\Re \int_{-\infty}^{\infty} f(x) dx\). Now consider the semicircular contour \(C\) consisting of a segment on the real axis from \(-R\) to \(R\), and an arc \(\gamma\) in the upper half plane connecting the two endpoints as shown below.
> {{< image src="/images/residue-theorem/contour.png" position="center">}}
> Then we have that
> \[
    \oint_{C} f(z) dz = \int_{-R}^{R} f(x) dx + \int_{\gamma} f(z) dz
\]
> and by the residue theorem, \(\oint_{C} f(z) dz = 2 \pi i \text{Res}(f, i) = \pi e^{-1}\), so
> \[
    \int_{-R}^{R} f(x) dx = \frac{\pi}{e} - \int_{\gamma} f(z) dz
\]
> As \(R\) approaches infinity, it can be shown through bounding that \(\int_{\gamma} f(z) dz\) vanishes, so
> \[
    \begin{align}
    \int_{-\infty}^{\infty} \frac{\cos(x)}{1+x^2} dx &= \Re \int_{-\infty}^{\infty} f(x) dx\\
    &= \frac{\pi}{e}
    \end{align}
\]

Since the residue theorem also works if there are an infinite number of singularities (as long as they are isolated), we can "work in reverse" and instead find the value of an infinite sum by calculating a contour integral.

Let's say we wanted to find the value of the sum
\[
    \sum_{x \in X} f(x)
\]
through the residue theorem. By the theorem, \(\sum_a \text{Res}(F, a) = \frac{1}{2\pi i}\oint_{C} F(z) dz\), so we want to find a function \(F(z)\) such that

1. Every \(x \in X\) is a singularity of \(F(z)\)[^1]
2. The residue of \(F(z)\) at each \(x \in X\) is \(f(x)\)

To construct such an \(F(z)\), we first consider another function \(g(z)\) which has set of roots \(X\). Then, we can write
\[
    g(z) = g_1(z) \left(z - x_0\right)^{n_0} \left(z - x_1\right)^{n_1} \left(z - x_2\right)^{n_2} \dots
\]
where \(g_1(z) \ne 0\) for all \(z\).

Now, consider taking the logarithm then the derivative.

\[
    \begin{align}
    \frac{d}{dz} \ln g(z) &= \frac{d}{dz} \left( \ln g_1(z) + n_0 \ln \left(z - x_0\right) + n_1 \ln \left(z - x_1\right) + n_2 \ln \left(z - x_2\right) + \dots \right)\\
    &= \frac{d}{dz} \ln g_1(z) + \frac{n_0}{z - x_0} + \frac{n_1}{z - x_1} + \frac{n_2}{z - x_2} + \dots
    \end{align}
\]

We now have a function that has poles at all \(x \in X\), with residue equal to \(n\), the order of the zero. If all the zeroes have order 1, then \(f(z) \frac{d}{dz} \ln g(z) = f(z) \frac{g^\prime(z)}{g(z)}\) will satisfy the conditions for \(F(z)\).[^2]

As an example, we can try calculating \(\sum_{k=1}^{\infty} \frac{1}{k^2}\). Here, \(f(x) = \frac{1}{x^2}\), and we can choose \(g(x) = \sin(\pi x)\). We should first confirm that the zeroes of \(\sin(\pi x)\) all have order 1:
\[
    \begin{align}
    \lim_{x \to n} \frac{\sin(\pi x)}{x - n} &= \lim_{x \to n} \frac{\sin(\pi x)}{x - n}\\
    &= \lim_{x \to n} \frac{\pi \cos(\pi x)}{1}\\
    &= \pm \pi
    \end{align}
\]
Now we can define \(F(z) = f(z) \frac{g^\prime(z)}{g(z)} = \frac{pi}{z^2} \cot(\pi z)\).

With \(C\) being a contour that envelopes all singularities of \(F(z)\),
\[
    \begin{align}
    \oint_{C} F(z) dz &= \oint_{C} \frac{\pi}{z^2} \cot(\pi z) dz\\
    &= \sum_{k=-\infty}^\infty \text{Res}\left(\frac{\pi}{z^2} \cot(\pi z), k\right)\\
    &= 2 \sum_{k=1}^\infty \frac{1}{k^2} + \text{Res}\left(\frac{\pi}{z^2} \cot(\pi z), 0\right)
    \end{align}
\]

We have a pesky residue at \(z = 0\) that we will need to take care of. The Laurent expansion of \(\cot(z)\) around \(z = 0\) is
\[
    \frac{1}{z} - \frac{z}{3} - \frac{z^3}{45} - \frac{2z^5}{945} + O\left(z^7\right)
\]
so
\[
    \frac{\pi}{z^2} \cot(\pi z) = \frac{1}{z^3} - \frac{\pi^2}{3z} - \frac{\pi^4z}{45} - \frac{2\pi^6z^3}{945} + O\left(z^5\right)
\] 
and it is plain to see that \(\text{Res}\left(\frac{\pi}{z^2} \cot(\pi z), 0\right) = -\frac{\pi^2}{3}\).

Now, all that is left is to evaluate the contour integral without the residue theorem. As with the example above, a common way to do this is to bound the value of the integral and show that it approaches 0 as the contour expands.

From here onwards, let \(n\) be a positive integer. Consider the square contour \(C\) with side length \(2n+1\) centered at 0. We will bound the value of the integral by bounding the value of \(\vert\cot\left(\pi x\right)\vert\) along the edges of the square.

On the top and bottom edges,
\[
    \begin{align}
    \left\vert\cot\left(\pi \left(x \pm \left(n+1/2\right)i\right)\right)\right\vert &= \left\vert\frac{i\left(e^{\pi i \left(x \pm \left(n+1/2\right)i\right)}+e^{-\pi i \left(x \pm \left(n+1/2\right)i\right)}\right)}{e^{\pi i \left(x \pm \left(n+1/2\right)i\right)}-e^{-\pi i \left(x \pm \left(n+1/2\right)i\right)}}\right\vert\\
    &= \left\vert\frac{e^{2\pi i \left(x \pm \left(n+1/2\right)i\right)}+1}{e^{2\pi i \left(x \pm \left(n+1/2\right)i\right)}-1}\right\vert\\
    &= \frac{\left\vert e^{2\pi i \left(x \pm \left(n+1/2\right)i\right)}+1\right\vert}{\left\vert e^{2\pi i \left(x \pm \left(n+1/2\right)i\right)}-1\right\vert}\\
    &\le \frac{ e^{\mp \pi \left(2n+1\right)} + 1}{\left\vert e^{\mp \pi \left(2n+1\right)}-1\right\vert}\\
    &\le 2
    \end{align}
\]

On the left and right edges,
\[
    \begin{align}
    \left\vert\cot\left(\pi \left(ix \pm \left(n+1/2\right)\right)\right)\right\vert &= \left\vert\frac{i\left(e^{\pi i \left(ix \pm \left(n+1/2\right)\right)}+e^{-\pi i \left(ix \pm \left(n+1/2\right)\right)}\right)}{e^{\pi i \left(ix \pm \left(n+1/2\right)\right)}-e^{-\pi i \left(ix \pm \left(n+1/2\right)\right)}}\right\vert\\
    &= \left\vert\frac{e^{2\pi i \left(ix \pm \left(n+1/2\right)\right)}+1}{e^{2\pi i \left(ix \pm \left(n+1/2\right)\right)}-1}\right\vert\\
    &= \left\vert\frac{-e^{-2\pi x}+1}{-e^{-2\pi x}-1}\right\vert\\
    &= \left\vert 1 - \frac{2}{e^{-2\pi x}+1}\right\vert\\
    &\le 1\\
    \end{align}
\]

Therefore,
\[
    \begin{align}
    \left\vert \oint_{C} \frac{\pi}{z^2} \cot(\pi z) dz \right\vert &\le \oint_{C} \left\vert \frac{\pi}{z^2} \cot(\pi z) \right\vert \left\vert dz \right\vert \\
    &\le \oint_{C} \left\vert \frac{2\pi}{\left(n+1/2\right)^2} \right\vert \left\vert dz \right\vert\\
    &= \frac{2\pi}{\left(n+1/2\right)^2}\left(4\left(2n+1\right)\right)\\
    &= \frac{16\pi}{n+1/2}\\
    \end{align}
\]
and as the contour expands to cover all singularities, \(n\) approaches infinity, so
\[
    \oint_{C} \frac{\pi}{z^2} \cot(\pi z) dz = 0
\]
and we finally get
\[
    \begin{align}
    2 \sum_{k=1}^\infty \frac{1}{k^2} &= -\text{Res}\left(\frac{\pi}{z^2} \cot(\pi z), 0\right)\\
    &= \frac{\pi^2}{3}\\\\
    \sum_{k=1}^\infty \frac{1}{k^2} &= \frac{\pi^2}{6}
    \end{align}
\]

Similarly, the values of \(\oint_{C} \frac{\pi}{z^{2n}} \cot(\pi z) dz\) also disappear, so we can calculate the sum of the reciprocals of any even power.

\[
    \begin{align}
    \sum_{k=1}^\infty \frac{1}{k^4} &= -\frac12\text{Res}\left(\frac{\pi}{z^4} \cot(\pi z), 0\right)\\
    &= \frac{\pi^4}{90}\\
    \sum_{k=1}^\infty \frac{1}{k^6} &= -\frac12\text{Res}\left(\frac{\pi}{z^6} \cot(\pi z), 0\right)\\
    &= \frac{\pi^6}{945}\\
    &\;\;\vdots
    \end{align}
\]

Now, instead of summing over the integers, we can also sum over some less conventional sets. For example, let's say we want to calculate \(\sum_{x=\tan x, x \ne 0} \frac{1}{x^2}\), the sum of the reciprocal squares of all fixed points of the tangent function. In this case \(f(x) = \frac{1}{x^2}\) again, and we can set \(g(x) = \sin x - x \cos x\) to avoid unnecessary singularities from \(\tan x\). We now have the function \(F(z) = f(z) \frac{g^\prime(z)}{g(z)} = \frac{\sin z}{z(\sin z - z \cos z)}\). As with before,
\[
    \begin{align}
    \oint_{C} F(z) dz &= \oint_{C} \frac{\sin z}{z(\sin z - z \cos z)} dz\\
    &= \sum_{x = \tan x} \text{Res}\left(\frac{\sin z}{z(\sin z - z \cos z)}, x\right)\\
    &= \text{Res}\left(\frac{\sin z}{z(\sin z - z \cos z)}, 0\right) + \sum_{x=\tan x, x \ne 0} \frac{1}{x^2}
    \end{align}
\]

It can be shown similarly that \(\oint_{C} \frac{\sin z}{z(\sin z - z \cos z)} dz\) decreases to 0 as the contour expands to cover all singularities, so we have

\[
    \begin{align}
    \sum_{x=\tan x, x \ne 0} \frac{1}{x^2} &= -\text{Res}\left(\frac{\sin z}{z(\sin z - z \cos z)}, 0\right)\\
    &= \frac15
    \end{align}
\]

Of course, this method will not work for every possible choice of \(f(x)\) and \(g(x)\) (for example, you cannot evaluate \(\sum_{k=1}^\infty \frac{1}{k^3}\) because the contour integral cannot be evaluated nicely on only the right half), but it's still cool :)

[^1]: ideally \(F(z)\) should be chosen such that the singularities are "nice" enough, because separating the residue of singularities in \(X\) and not in \(X\) will become troublesome otherwise
[^2]: of course, there are more things to consider, like how \(f(x)\) contributes to the singularities of \(F(x)\), but most \(f(x)\) will not drastically impact the behavior of \(F(x)\)