---
layout: default
title: All Posts
permalink: /posts/
---

# All Publications

<a href="/" class="social-btn">&larr; Back to Home</a>

---

## 🎯 CTF Writeups
<ul>
  {% for post in site.categories.CTF %}
    <li>
      <a href="{{ post.url }}">{{ post.title }}</a> - {{ post.date | date: "%Y-%m-%d" }}
    </li>
  {% endfor %}
</ul>

## 🛡️ CVE Disclosures
<ul>
  {% for post in site.categories.CVE %}
    <li>
      <a href="{{ post.url }}">{{ post.title }}</a> - {{ post.date | date: "%Y-%m-%d" }}
    </li>
  {% endfor %}
</ul>

## 💀 Exploits & Research
<ul>
  {% for post in site.categories.Exploits %}
    <li>
      <a href="{{ post.url }}">{{ post.title }}</a> - {{ post.date | date: "%Y-%m-%d" }}
    </li>
  {% endfor %}
</ul>
