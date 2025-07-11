---
layout: post
title: "[RootMe] Ethernet - Frame"
date: 2025-07-11 10:00:00 +0530
categories: [RootMe, Network]
tags: [hexdump, base64, authentication]
pin: false
---
# 🧩 Challenge: ETHERNET - frame

**Platform:** RootMe  
**Category:** Network  
**Difficulty:** Very Easy  
**Points:** 10  

**Attachment:** `ch12.txt`

---

### Step 1: Analyze the File

The file is in raw hex format.

![Hexdump](/assets/img/rootme/ethernet-frame/hexdump.png)

We’ll use `xxd` on Linux to decode it.

---

### Step 2: Decode Hexdump

Using `xxd -r -p ch12.txt`, we get what looks like a Base64-encoded string:
`Y29uZmk6ZGVudGlhbA==`
![DecodedDump](assets/img/rootme/ethernet-frame/xxd_decoded.png)

Which is evident from the trailing `==`.

---

### Step 3: Decode Base64

Using:

`echo Y29uZmk6ZGVudGlhbA== | base64 -d`

![Base64Decoded](assets/img/rootme/ethernet-frame/base_decoded.png)

Ta Da!

---

### Step 4: Refer to Additonal Resources

![resources](assets/img/rootme/ethernet-frame/resources.png)

These are the additional resources provided, let's refer to the 
"HTTP basic authentication and digest authentication" document

![digestauth](assets/img/rootme/ethernet-frame/digest_auth.png)

Hence, the final answer is: `confi:dential`


