+++
title = "Tones in East Asian Languages"
date = "2025-09-11T18:06:12+08:00"
author = "azazo"
description = ""
showFullContent = false
readingTime = false
hideComments = false
draft = true
+++

(Mandarin) Chinese famously has four tones. It is also arguably the most well known tonal language, both in terms of how many speakers it has and how many people know of it. I like tonal languages a lot, and I also happen to be a native speaker of Mandarin Chinese, so I thought I would spend some time talking (writing?) about tones in Chinese, but that isn't nearly enough content, so I'll be discussing some other languages as well.

# Tones
It would do us good to first explain what tone is. Tonal languages assign a *pitch contour* to every syllable, and differences in pitch can indicate differences in meaning. Notably, it is different from intonation or stress, in ways that I am probably not qualified enough to explain.

Mandarin Chinese has four tones (or five, depending on how you count[^1]).

# Chinese
Just a brief primer: historical reconstructions of Chinese are generally divided into four phases, depending on the major sources they were reconstructed from [which I have put in square brackets]:
1. Old Chinese (OC), ~before Han dynasty [rhymes of *Shijing*, a collection of poems; Early Middle Chinese]
2. Early Middle Chinese (EMC), ~Sui to Tang dynasty [Qieyun, Guangyun, various rime dictionaries]
3. Late Middle Chinese (LMC), ~Song dynasty [Yunjing, various rime tables]
4. Early Mandarin (EM), ~Yuan dynasty [Zhongyuan Yinyun]
The finer details really aren't that important. It's fine to just know the names of these four phases.

Tones started to definitively exist in Chinese starting around the Sui dynasty (581 to 618 AD). In what is arguably one of the first rime dictionary (basically pronunciation guide) of Chinese published in 601, the *Qieyun* (切韵), words were divided among four tones: *ping, shang, qu, and ru* (平 level, 上 rising, 去 departing, 入 entering respectively). We can say with certainty that this distinction was a tonal one instead of basing off another phonological feature because TODO
1. During the Tang dynasty, various Japanese monks[^2] described the four tones with vocabulary that imply a pitch difference.
2. They evolved to become tonal distinctions in every Chinese dialect (sort of a circular argument, but oh well)

In the popular Baxter's reconstruction of MC, the shang tone is marked with a trailing X and the qu tone is marked with a trailing H, while the ping and ru tones are unmarked (they can be disambiguated by the presence of a consonant coda). They can also be notated with a pre/post super/subscript cup: the cup faces inwards and is placed at the four corners from the bottom left to the bottom right depending on whether the syllable is ping, shang, qu, or ru respectively. I find this notation ugly, so I will not be using it.

So, we can say that differences in tones were prominent enough in EMC to be recorded down systematically. But what about before EMC? It is generally believed that OC lacked tonal distinctions, instead having a more permissive syllable structure that allowed consonant clusters at the end of syllables, which eventually evolved into tones. In fact, to my knowledge, no popular reconstruction of OC explicitly asserts the existence of tonal categories.

The most well-accepted hypothesis for how OC codas developed into MC tones is that
1. all codas except nasals and plosives disappeared, with syllables plosive codas becoming ru tone
2. syllables with a glottal stop coda, *-ʔ, became shang tone
3. syllables with a coda of *-s became qu tone
4. all other syllables became ping tone
This hypothesis is well-supported with evidence from Vietnamese, which underwent a similar tonogenesis process, and borrowings from other languages being adapted to fit Chinese phonology. In particular, various borrowings from other languages with coda s carry qu tone syllables, and some early Chinese loanwords into Korean have coda -s for Middle Chinese departing tone.

It is important to note that the ping, shang, qu, and ru tones do *not* correspond to the four tones in modern Mandarin, even though coincidentally there are four major categories in both MC and Mandarin. The four tones of Mandarin were derived from interactions between the initials of a syllable and its tone. Before discussing exactly how the four tones of MC evolved into the four tones of Mandarin today, let's take a brief look at MC phonology first. I'll try to keep it short, since we won't be concerned with most of the details.

EMC is commonly reconstructed to have about somewhere about 40 initials[^3]. The stops have both a voicedness and an aspiration distinction, unlike Mandarin. These are referred to as 全清, 次清, 全濁, and 次濁 ("full clear" voiceless unaspirated, "secondary clear" voiceless aspirated, "full opaque" voiced, and "secondary opaque" nasals/laterals collectively referred to as sonorants). The initials are also broadly divided by their place of articulation into 唇音, 舌音, 半舌, 齒音, 半齒, 牙音, and 喉音 ("lip sound", "tongue sound", "half tongue", "front teeth sound", "half teeth", "back teeth sound", "throat sound") whose correspondences to modern terms should hopefully be clear (the halfs are probably just for extra consonants that there wasn't space for).

For LMC the system was simplified down into 36 initials by creating some new sets (labial fricatives arised as "soft lip" sounds) and merging other sets (retroflex dental plosives disappeared), resulting in a rather neat and nice system.

{{< figure src="/images/tones/36.png" caption="Image from Wikipedia">}}

You might notice that there are now two columns titled 清 and 濁. It's okay, we don't need to worry about that :)

The finals of EMC and LMC are a bit more complicated, but we really only need to care about the codas. MC syllables could have nasal or plosive codas, and importantly ru tone syllables all have plosive codas. Meanwhile, ping, shang, and qu syllables could have either no coda or a nasal coda.

## Mandarin

With that all out of the way, here is how tones evolved from MC to Mandarin:

| MC initial \ MC tone                | ping | shang | qu | ru                      |
|-------------------------------------|------|-------|----|-------------------------|
| 清 "clear" (voiceless)              | 1    | 3     | 4  | 1, 2, 3, 4 (no pattern) |
| 次濁 "secondary opaque" (sonorants) | 2    | 3     | 4  | 4                       |
| 全濁 "fully opaque" (voiced)        | 2    | 4     | 4  | 2 (sometimes 4)         |

Wow. With the exception of the ru tone, most syllables can be sorted nicely into the four Mandarin tones (with some exceptions of course). This feels like a very anticlimatic ending to the long spiel about MC phonology, so here are some examples with Baxter's reconstructions:

1. 三 *sam (voiceless, ping) > san1
2. 迷 *mej (sonorant, ping) > mi2
3. 平 *bjaeng (voiced, ping) > ping2
4. 請 *tshjengX (voiceless, shang) > qing3
5. 買 *meaX (sonorant, shang) > mai3
6. 旱 *hanX (voiced, shang) > han4
7. 旦 *tanH (voiceless, qu) > dan4
8. 妙 *mjiewH (sonorant, qu) > miao4
9. 佩 *bwojH (voiced, qu) > pei4
10. 八 *peat, 博 *pak, 筆 *pit, 必 *pjit (all voiceless, ru) > ba1, bo2, bi3, bi4
11. 没 *mwot (sonorant, ru) > mo4
12. 十 *dzyip, 涉 *dzyep (both voiced, ru) > shi2, she4

As for why the initial influenced the development of tone, voiced consonants tend to decrease the fundamental frequency of the following vowel, resulting in a split in pitch between syllables with voiced and voiceless initials. Then, as MC lost voiced initials, the change in pitch was more set in stone as a way to differentiate between words and became the tones of Mandarin.[^4]

A brief tangent: there are many fun things you can do with this information coupled with some knowledge on how initials evolved from MC to Mandarin. You can go the other way and kind of guess how a word was pronounced in MC from its Mandarin reading. You can explain why certain syllables like jiang2 never show up in Mandarin:

- jiang2 would need to have an opaque ping MC reflex, as ru syllables do not have nasal codas
- the reflex would probably be full opaque, as it is unlikely for a sonorant to evolve into j /ʨ/
- full opaque initials evolved into voiceless initials with aspiration if the syllable was of ping tone and without otherwise
- so our hypothetical jiang2 MC reflex would be full opaque ping, but full opaque ping would evolve into aspirated tone 2 while j /ʨ/ is unaspirated; a contradiction!

All of this is very fun and interesting to me.

## Dialects
Broadly speaking, Chinese dialects can be grouped into 8 families based on how they evolved from MC.[^5] The 8 families are, roughly in order of number of native speakers:
1. Mandarin, spoken in northern and southwestern China
2. Min, spoken in mainly Fujian (Hokkien, Teochew, ...)
3. Wu, spoken in Shanghai, Zhejiang, and surrounding areas (Shanghainese, Suzhounese, ...)
4. Yue, spoken in Guangdong, Guangxi, and surrounding areas (Cantonese, ...)
5. Jin, spoken in Shanxi and surrounding areas
6. Gan, spoken in Jiangxi and surrounding areas (Nanchang dialect, ...)
7. Hakka, spoken in Fujian, Guangdong, and surrounding areas
8. Xiang, spoken in mainly Hunan (Changsha dialect, ...)

If you are familiar with Chinese geography, you might notice that most of these families are based in southeastern China. This is probably due to both geographical and historical reasons: south China has a more difficult terrain as compared to north China so people from different places would not be able to communicate and form linguistic homogeneity easily, and historically the capitals of Chinese dynasties were all located in the north.

No modern dialect has retained the same distinction of the four tones from MC; they have almost all split and recombined into different categories.

# Tibetan


# Middle Korean

# Vietnamese, Tai, Hmong-Mien languages

# Bonus: Seoul Korean



[^1]: the fifth tone is referred to as 轻声 (qíng shéng, literally soft tone). it is only used for certain words of low "lexicality" (mostly particles), and varies in tone contour a lot based on the tone of the preceding word. as such, some people dont really view it as a separate tone
[^2]: i find it kind of funny that they were so enthused by chinese phonology. its probably because as buddhist monks, they interact with sanskrit texts quite often, and so there was a natural enthusiasm for sanskrit phonology which extended to chinese
[^3]: theres no precise number because rime dictionaries dont explicitly say what character began with what sound, only that two characters began with the same sound
[^4]: this is actually a very common trigger for tonogenesis
[^5]: this means that mutually intelligible dialects will be grouped into the same family. in fact i think some people dont use the term "dialect" and instead use "topolect" or "variety" for this reason. if we take mutual intelligibility as the criteria for differentiating between language and dialect there would be hundreds of languages in china