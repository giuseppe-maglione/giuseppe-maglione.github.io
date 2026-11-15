---
layout: default
title: Home
---

# Offensive Security & Vulnerability Research 👾

Welcome. I am an Offensive Security researcher. This space is dedicated to documenting my zero-day discoveries, exploit development, and methodologies from various Capture The Flag (CTF) engagements.

### What you will find here:
* **My CVE Disclosures**: Technical descriptions, Proof of Concepts (PoCs), and disclosure timelines for vulnerabilities I have discovered and reported.
* **CTF Writeups**: Advanced offensive techniques and step-by-step compromises for platforms like HackTheBox and TryHackMe.
* **Red Teaming Notes**: Custom scripts, evasion techniques, and payload crafting.

---

### Recent Publications
<ul>
  {% for post in site.posts %}
    <li>
      <a href="{{ post.url }}">{{ post.title }}</a> - {{ post.date | date: "%Y-%m-%d" }}
    </li>
  {% endfor %}
</ul>
