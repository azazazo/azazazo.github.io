+++
title = "I Don't Like The NUS NextBus App So I Did Something About It"
date = "2024-10-19T14:23:45+08:00"
author = "azazo"
# cover = ""
# tags = ["rev"]
description = "This doesn't violate the AUP... right...?"
showFullContent = false
readingTime = false
hideComments = false
+++

## introduction

NUS is a big[^1] university. Fortunately, there is an internal shuttle bus service that ferries students[^2] to and fro differnet locations, along with [a handy app](https://play.google.com/store/apps/details?id=nus.ais.mobile.android.shuttlebus) (the titular NUS NextBus) that displays bus routes and arrival timings.

Unfortunately, this app doesn't seem to be very good.[^3]

{{< image src="/images/nextbus/ratings.png" >}}

Recently, after being fed up with Google Maps not being able to display bus routes, I found a [pretty cool website](https://busrouter.sg/) that not only shows all public bus stops and routes in Singapore, but also has a nice UI. So I thought, "hey wouldnt it be cool if i made something like this but for nus buses", and got to work.

## ok now the actual content

First I needed an API for NUS ISB timings, however after a cursory search it quickly became evident that there is no public API documentation available.[^4] Truly unfortunate, but that won't stop me. I did what any sensible person would do, and decided to reverse engineer the app, to find out where it was getting its information from.[^5]

As I am an iPhone user, I first considered reversing the iOS version of the app, but it seems that it is not yet possible to jailbreak devices running iOS 16.6 and up, so I ended up having to use the Android version. I grabbed the package name from Play Store, put it into a (somewhat shady) website to download the APK, and now everything's ready.

(Just in case you don't know what an APK is: APK (Android PacKage) is a file format used primarily to install apps. It contains all the necessary code and resources to run an app, and is kind of like an exe for Android.)

I'm using [jadx](https://github.com/skylot/jadx), a pretty good APK decompiler. After loading in the APK, we can look at the structure of the source code directories.

{{< image src="/images/nextbus/tree.png" position="center" >}}

We'll first look at the surreptitiously named `nus.ais.mobile.android.shuttlebus`, which is where the main code for the app should be stored. `shuttlebus` has `MainActivity` and `MainApplication`, which sound rather important.

(An application in Android is divided up into several *activities*, which is "a single, focused thing that the user can do". To use an analogy, if an app was a play, an activity would be like a scene. `MainActivity`, like the name suggests, contains the code for the main activity, which is ran when the app is opened.)

However, `MainActivity` doesn't seem to contain much either:

```java
/* irrelevant code removed */

/* loaded from: classes2.dex */
public final class MainActivity extends ReactActivity {
    @Override // com.facebook.react.ReactActivity
    protected String getMainComponentName() {
        return "nusnextbusv2";
    }

    @Override // com.facebook.react.ReactActivity
    protected ReactActivityDelegate createReactActivityDelegate() {
        SplashScreen.show(this);
        return new DefaultReactActivityDelegate(this, getMainComponentName(), DefaultNewArchitectureEntryPoint.getFabricEnabled());
    }
}
```

It turns out (as you might have guessed from the various type names, method names and comments) that this app is a React Native app[^6], and thus the source code is not contained within the decompiled Java files. Doing a quick Google search, I learn that all the JavaScript source code is bundled into a file called `index.android.bundle`. Sure enough, when I look into the resources folder, it's there. Unfortunately, it appears to be obfuscated in some way.

{{< image src="/images/nextbus/bundle.png" position="center" >}}

No matter; I extracted out the file from the APK to work with it directly. Using the `file` command helps to identity what kind of file this is:

```shell
❯ file index.android.bundle
index.android.bundle: Hermes JavaScript bytecode, version 96
```

Turns out that the source code has been turned into bytecode for Hermes, a "JavaScript engine optimized for React Native". I used [hermes-dec](https://github.com/P1sec/hermes-dec) to decompile this; unfortunately it's not very good, but its still readable.

```shell
hbc-decompiler index.android.bundle index_decomp.js
```

Doing that gives us a giant 21MB file with close to 560 thousand lines of messy, (unintentionally) obfuscated JavaScript code. So I did the most sensible thing, and spent close to half a day scanning through it.

I found
- email addresses and passwords
- an `encode()` function
- coordinates of all bus stops
- list of points of interest
- closest bus stops to every point of interest

and more importantly
- the API URL
- list of endpoints and their parameters

I gave it a try, and...

```shell
❯ curl -X GET "https://nnextbus.nus.edu.sg/BusStops"
Unauthorized Access
```

Not entirely unexpected. Fortunately, it was relatively easy to find the correct credentials for authentication, and now finally...

{{< image src="/images/nextbus/authorised.png" position="center" >}}

It works![^7]

## wait why didnt you just inspect the network traffic using an emulator or something

Good question. I don't know. If I *had* to give a reason it would probably be

1. I don't have Android Studio installed on this computer yet
2. I don't want to figure out how to inspect the network traffic

Also by decompiling the Hermes bytecode I found a lot more fun stuff, so it was worth it.

## the end?

yea thats it sorry

When I first started writing this a while ago (it's December now time sure flies)[^8] I was planning to work on a web version of NextBus with a friend, but after exams the we both lost motivation, and everything kind of fell through.

I also contemplated adding a section where I explore the email accounts I found, but quickly realised that maybe it's not a good idea to document my (somewhat) illegal actions. Getting my hands on a jailbroken iOS device is also... unfeasible for now so I couldn't explore iOS decompilation either.

So that's the end of this post. Thanks for reading?

[^1]: citation needed
[^2]: unrelated but [there was a brief period of time where they banned tourists from the buses](https://www.channelnewsasia.com/singapore/nus-chinese-tourists-visitors-access-utown-food-courts-shuttle-bus-golden-week-holiday-4639906), which is pretty funny to me
[^3]: personally ive never had any issues with it but i need a reason for doing this other than "im bored and i dont want to revise for my exams" soooooo
[^4]: actually i did find [this](https://suibianp.github.io/nus-nextbus-new-api/) but its not official so
[^5]: this also makes me wonder who made the app; i cant find any info on the author other than "nus"
[^6]: no wonder why its so disliked
[^7]: credentials censored for obvious reasons
[^8]: im not joking when i said i wrote 90% of this post in one day then waited two months to write the last section