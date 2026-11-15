---
layout: default
title: Home
---

# Offensive Security & Vulnerability Research 👾

Welcome. I am an Offensive Security researcher. This space is dedicated to documenting my zero-day discoveries, exploit development, and methodologies from various Capture The Flag (CTF) engagements.

<div style="margin: 30px 0;">
  <a href="https://github.com/giuseppe-maglione" target="_blank" class="social-btn">GitHub</a>
  <a href="https://tryhackme.com/p/giuu" target="_blank" class="social-btn">TryHackMe</a>
  <a href="https://www.linkedin.com/in/giuseppe-maglione-48748a23b/" target="_blank" class="social-btn">LinkedIn</a>
</div>

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
