+++
title = "Conic sections' intersections"
date = "2025-11-17T14:10:12+08:00"
author = "azazo"
description = "another short filler post"
tags = ["math"]
showFullContent = false
readingTime = false
hideComments = false
draft = true
+++

{{< math >}}

# introduction

A while ago I saw a YouTube video about solving planar geometry problems by thinking out of the plane; by adding a third dimension to the problem they can be solved with relative ease.

Here is an example: given three circles such that there is a region contained in all three circles, prove that the three lines connecting the intersecting points of each pair of circles intersect at a common point.

TODO: video here

The solution introduced in the video was to extend the circles into spheres with the same radius and centers on the original plane. The spheres intersect in circles, which are viewed as lines when projected down into the original plane. For a pair of circles, their intersecting circle will meet the remaining circle at two points, which when projected down, becomes the common point of intersection as desired.

This is quite a neat proof, but of course, it has its flaws. For one, if there is no region inside all three circles, then the proof fails as the intersecting circle of two spheres will not intersect the third circle. The most "common" way to prove this result would probably be using the radical axis. Let's first introduce some preliminary concepts.

The *power* of a point \(P\) with respect to a circle \(\omega\) with radius \(r\) and center \(O\) is defined by the product of the two lengths along a straight line through \(P\) and intersecting \(omega\) (a tangent line is counted as having an intersection with multiplicity two at its point of tangency). There is no need to specify the line, since all choices lead to the same value for the power, a result that can be proved by similar triangles.

Because all choices for the line give the same value, we can pick a tangent line and define the power to be
\[
    \Pi_\omega(P) = \overline{PC}^2 - r^2
\]
where \(C\) is the center and \(r\) is the radius of \(\omega\). This follows from the Pythagorean theorem applied to the radius, tangent line, and \(\overline{PC}\).

For two circles \(\omega_1\) and \(\omega_2\), their *radical axis* is defined to be the locus of all points such that \[
    \Pi_{\omega_1}(P) = \Pi_{\omega_2}(P)
\]
As the name implies, this locus is a straight line (which can be proved with vectors [as demonstrated on Wikipedia](https://en.wikipedia.org/wiki/Radical_axis#Properties)), and passes through the intersection points of \(\omega_1\) and \(\omega_2\) should they intersect.

Now to prove our original problem, we can replace the lines joining the intersection points with the radical axis. Since two lines must always intersect unless parallel, the radical axis of \(\omega_1\) and \(\omega_2\) and the radical axis of \(\omega_2\) and \(\omega_3\) must meet at a point. At this point \(P\), we will have that \[
    \Pi_{\omega_1}(P) = \Pi_{\omega_2}(P) = \Pi_{\omega_3}(P) \implies \Pi_{\omega_1}(P) = \Pi_{\omega_3}(P)
\]
and so \(P\) is also on the radical axis (and hence line joining intersection points) of \(\omega_1\) and \(\omega_3\), completing our proof. While this proof may not be as simple to understand as the 3D one, there is still a certain elegance to it that I appreciate very much.

# the problem

More recently, I saw a tweet with the following claim:

> （軸が互いに平行な）３つの放物線が、それぞれ他の２つと２点で交わっているとする。各ペアの２つの交点を通る直線をすべてのペアについて３本描くと、それらは一点で交わる。
> *Suppose there are three parabolas (with axes of symmetry parallel to one another) that each intersect the other two at two points. If we draw three straight lines through the two points of intersection for each pair, these lines will intersect at a single point.*

