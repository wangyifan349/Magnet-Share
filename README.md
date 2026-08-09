# 🧲 Magnet Share

A lightweight **FastAPI + SQLite** website for sharing, managing, and searching Magnet URIs.

Magnet Share stores only lightweight metadata: **Magnet URIs, BTIH / Infohash values, titles, descriptions, users, and timestamps**. It does **not** host the actual movies, disk images, archives, datasets, or other large files referenced by those magnets.

Users can create accounts, manage their own magnet lists, remove entries they created by mistake, search for other users, and search for magnets by URI, Infohash, or title.

🔗 Repository:

```text
https://github.com/wangyifan349/Magnet-Share
```

---

## 🧭 Features

- 👤 User registration, sign-in, and sign-out
- 🗂️ A separate magnet list for every user
- ➕ Create Magnet entries
- 🗑️ Delete Magnet entries created by your own account
- 🔎 Search usernames
- 🧲 Search full Magnet URIs
- #️⃣ Search BTIH / Infohash values
- 🏷️ Search magnet titles
- 🧠 Fuzzy ranking with Longest Common Subsequence (LCS)
- 🔴 User search results are marked in red
- 🟢 Magnet search results are marked in green
- 🌐 Every user has a public profile showing all magnets they created

Magnet URIs can be opened with BitTorrent clients such as:

- [qBittorrent](https://www.qbittorrent.org/)
- [qBittorrent Download](https://www.qbittorrent.org/download)

---

## 🧩 BitTorrent and Magnet Links

**BitTorrent (BT)** is a peer-to-peer (P2P) file distribution protocol.

A traditional file download normally looks like this:

```text
Server  ───────────────> User
```

The central server must send the actual file data to every downloader.

If a file is 20 GB and many users download it at the same time, the server has to continuously provide a large amount of outbound bandwidth.

BitTorrent distributes data differently.

A file is split into many pieces, and multiple peers can exchange pieces they already have:

```text
                ┌──────── Peer A
                │
Peer B ─────── File Pieces ────── Peer C
                │
                └──────── Peer D
```

A downloader can obtain different pieces from multiple peers instead of downloading the entire file from one central server.

After a peer has downloaded some pieces, it can also upload those pieces to other peers.

This decentralized distribution model is one of the main reasons BitTorrent works well for large files.

---

## 🧲 What a Magnet URI Does

A Magnet URI is **not** the actual file.

A typical Magnet URI looks like this:

```text
magnet:?xt=urn:btih:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

The component:

```text
xt=urn:btih:
```

identifies BitTorrent content through a BTIH / Infohash value.

Magnet Share stores the Magnet URI and related metadata, not the actual files referenced by the Magnet URI.

The server is responsible for lightweight operations such as:

```text
Users
Titles
Descriptions
Magnet URIs
Infohash values
Search
```

The actual BitTorrent data transfer is handled by the user's own BitTorrent client and the P2P network.

---

## 🚀 Why Use BT / Magnet for Large Files?

Traditional HTTP file hosting can become expensive when many users download large files from one server.

For example, if a server has:

```text
100 Mbps
```

of outbound bandwidth, every concurrent downloader must share that limited server bandwidth.

In a healthy BitTorrent swarm, file data can instead come from multiple peers:

```text
Peer A uploads
Peer B uploads
Peer C uploads
Peer D uploads
...
```

This means the Magnet Share server does not need to carry the actual large-file traffic.

### 📦 Better Suited to Large Resources

Typical examples include:

- Linux ISO images
- Open-source software mirrors
- Large public datasets
- Public-domain videos
- Large development resource packages
- Files that you own or are authorized to distribute

Hosting all of those files directly on a small server can quickly consume its network capacity.

With BitTorrent, the server only needs to provide the lightweight Magnet index and search service.

### 🌱 Popular Resources Can Gain More Aggregate Upload Capacity

In a healthy swarm, when more peers that already have data are willing to upload it, the total upload capacity available to the swarm can theoretically increase.

Conceptually:

```text
More available peers
        ↓
More potential upload sources
        ↓
Less pressure on one central server
```

This does **not** mean download speed always increases linearly with the number of users.

Real-world BitTorrent speed still depends on factors such as:

- Number of seeders
- Peer upload bandwidth
- Network quality
- NAT and firewall configuration
- Client rate limits
- ISP conditions
- Swarm health

Compared with forcing every downloader to fetch an entire large file from one small server, BitTorrent is well suited to distributing traffic across many participating nodes.

---

## 🖥️ How This Project Works

```text
┌────────────────────────────┐
│       Magnet Share         │
│                            │
│  Users / Titles            │
│  Descriptions              │
│  Magnet / Infohash         │
│  Search / User Profiles    │
└─────────────┬──────────────┘
              │
              │ User opens a Magnet URI
              ▼
┌────────────────────────────┐
│ qBittorrent / BT Client    │
└─────────────┬──────────────┘
              │
              ▼
        BitTorrent P2P Network
```

Magnet Share itself:

- ✅ Stores Magnet URIs
- ✅ Stores titles and descriptions
- ✅ Provides search
- ✅ Provides per-user list management
- ✅ Provides public user profiles
- ❌ Does not host the large files referenced by Magnet URIs
- ❌ Does not proxy BitTorrent file traffic
- ❌ Does not download resources on behalf of users

---

## ⚡ Deploy and Run

Requires Python 3.10+.

Run these commands in order:

```bash
git clone https://github.com/wangyifan349/Magnet-Share
cd Magnet-Share
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python magnet_share.en.py    # English interface
```

For the Chinese interface, run `python magnet_share.zh.py` instead.

> **Note**: both files are self-contained single-file apps with their own embedded frontend —
> run whichever language you prefer.

Then open:

```text
http://0.0.0.0:8000
```

The application automatically creates the SQLite database in the current directory:

```text
magnet_share.db
```

---

## 🧪 Development and Testing

```bash
pip install -r requirements.txt
pip install -e ".[dev]"     # installs pytest + httpx
python -m pytest tests/ -v
```

The test suite runs the same scenarios against **both** the English
(`magnet_share.en.py`) and Chinese (`magnet_share.zh.py`) variants:

- health endpoint, registration, login, session (`/api/auth/*`)
- magnet creation, duplicate detection, delete ownership rules
- fuzzy search (LCS) and public user profiles
- infohash parsing (hex + Base32) and input-length validation

---

## ❤️ Sponsor

The developer supports and appreciates technologies built around open protocols, decentralized systems, peer-to-peer networking, and ideas such as BitTorrent and Magnet links.

If you find this project useful, agree with the idea of using BitTorrent / Magnet-based distribution, or simply want to support the author, voluntary sponsorships are welcome.

Sponsorship is simply a way to show appreciation for the project and the ideas behind it. It does not represent a promise of future development, maintenance, updates, support, or additional features.

### ₿ Bitcoin (BTC)

```text
bc1qxqfhumpqtnxrznkx9r4xsp8m6zsedtgusjns7p
```

### Ł Litecoin (LTC)

```text
ltc1qx60jqksl8pa38zmqjxau0vy04rqpjgfpn0xgw3
```

### ◆ Ethereum (ETH)

```text
0x2d92f9e4d8ac7effa9cd7cd5eccd364cac7c201b
```

Thank you for your support. ❤️
---

## 📄 License

This project is released under the **MIT License**.

See:

```text
LICENSE
```

---

## ⚠️ Usage Notice

This project is only an index for Magnet URIs and related metadata.

Only share content that you are legally allowed to distribute, such as open-source software, public-domain material, public datasets, Linux images, or files for which you have distribution rights.
