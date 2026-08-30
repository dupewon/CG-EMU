# 🛡️ CG-EMU (Vanguard Emulator)

*(Scroll down for English)*

---

## 🇹🇷 Türkçe

Selamlar,

Öncelikle bu GitHub reposunu sıfırdan düzenleme ve temizleme nedenim; projenin halen **aktif güncelleme ve geliştirme sürecinde** olmasıdır. 

Bildiğiniz üzere mimariyi tamamen değiştirdik ve kaya gibi sağlam bir altyapıya geçiş yaptık. Eski inline hook ve basit XOR şifrelemelerini bir kenara bırakıp; tamamen **IAT Hook**, **Riot JWKS üzerinden gerçek RSA sertifika doğrulaması** ve **raw protobuf frame** kullanan yeni bir sisteme geçtik. Bütün iletişim user-mode ve test-mode üzerinden, Vanguard'ın integrity taramalarına yakalanmadan sağlanıyor.

**Şu anki durum nedir?**
Sistem arka planda gayet güzel çalışıyor. Ancak, testlerimiz sırasında halen **VAL 5** ve **VAL 102** gibi ufak tefek bağlantı/oturum hatalarıyla karşılaşıyoruz. Şu an arka planda tam olarak bu temel sorunları fixlemekle uğraşıyoruz. 

Tamamen hatasız, stabil ve çalışır bir duruma geldiğinde projeyi hem **Release** hem de **Source Code** olarak burada paylaşacağım. Yarım yamalak, hata veren bir kodu size sunmak istemiyorum. O zamana kadar sabrınız için teşekkürler. Güncellemeleri takipte kalın.

---

## 🇬🇧 English

Hello everyone,

The primary reason for resetting and cleaning up this GitHub repository is that the project is still under **active development and constant updating**.

As some of you may know, we have completely overhauled the architecture to build something rock-solid. We abandoned the old inline hooking and basic XOR encryption methods. The new system now utilizes **IAT Hooking** (leaving code sections untouched), **real RSA certificate verification via Riot's JWKS**, and **true raw protobuf frames**. Everything is handled in user-mode and test-mode without tripping integrity scanners.

**Current Status:**
The emulator is running successfully in the background. However, during our active testing, we are still encountering a few minor issues, specifically **VAL 5** and **VAL 102** errors. We are actively working on fixing these underlying issues right now.

Once the project reaches a fully stable, flawless, and completely working state, it will be published here as both a **Release** and **Open Source Code**. I do not want to release a half-finished architecture that throws errors. Until then, thank you for your patience and stay tuned for updates.
