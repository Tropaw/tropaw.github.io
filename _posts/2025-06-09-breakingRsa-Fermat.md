---
layout: post
title: Breaking RSA with fermat method
date: 10/06/2025
categories: [ctf, crypto]
tag: [Crypto, ctf, algorithm]
author: Paw
description: You will understand how Fermat algorithm works x)
---


## What's RSA ? 

RSA in an asymmetric cryptographic algorithm that relies on the practical difficulty of factoring the product of two large prime numbers. A challenge using the "factoring problem", among the known methods to solve it is the famous Fermat algorithm, which we will discuss later in this topic.

---
 ## But how it works ?

In RSA, we use a pair of keys: one public and one private.
The public key is composed of the tuple (e, n).
where:

    n = p × q, the product of two large prime numbers.

    e is a small integer that is typically chosen as a constant (commonly 65537)

    To find how many prime numbers there are between 1 and n we will use φ(n)


$$\varphi(n) = (p-1)(q-1)$$

    The private key equals to "d", to find d we will use the equation:

$$
e \times d \equiv 1 \pmod{\varphi(n)}
$$

---
    
## Using Fermat algorithm

To use it the 2 larges prime numbers have to be close to each others.


Sooo, we want to find N, and you can do it very easly:

$$
b^2 = a^2 - N 
$$
> equals to N = a² - b² 


Here a small script that I make to help you to visualize.
>[here](https://github.com/Tropaw/Fermatheboss/blob/main/fermat.py)

 
