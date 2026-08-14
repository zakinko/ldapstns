# ldapstns

[English](README.md)

[STNS](https://stns.jp) のディレクトリを、ループバック上の LDAPv3 として
**macOS** の Open Directory に配信します。

```text
getpwnam(3) ─▶ opendirectoryd ─▶ ldap.bundle ─▶ 127.0.0.1:389 ─▶ ldapstns ─▶ STNS API
```

## なぜデーモンで、なぜ LDAP なのか

macOS のユーザーとグループの解決は `opendirectoryd` が行い、その拡張は
`/System/Library/OpenDirectory/Modules` のモジュールです。そこにあるのはすべて
Apple 署名のバンドルで、しかも System Integrity Protection がファイルの追加を
許さないディレクトリです。モジュールを書くのは「難しい」のではなく、
entitlement を取れば良いのでもなく、**できません**。

できるのは、既に同梱されているモジュールが理解する protocol を話すことです。
`ldap.bundle` はそこにあり、十分に枯れており、`127.0.0.1` に向けるのはコマンド
2 つです。そこで `ldapstns` は、STNS のディレクトリから応答する LDAPv3
サーバーになっています。

配置もこちらの設計判断ではありません。macOS は
`/System/Library/OpenDirectory/Mappings` のファイルで LDAP を自分のレコード型に
対応づけており、それが 2 つあります。

| | コンテナ | objectClass |
| --- | --- | --- |
| `Open Directory.plist` | `cn=users`, `cn=groups` | `inetOrgPerson` + `posixAccount` + `shadowAccount` + `apple-user` + `extensibleObject` の **AND** |
| `RFC2307.plist` | suffix 配下ならどこでも | `posixAccount` \| `inetOrgPerson` \| `shadowAccount` の **OR** |

属性名は両者でまったく同じ（`uid`、`uidNumber`、`gidNumber`、`cn`、
`homeDirectory`、`loginShell`、`memberUid`）で、違うのはコンテナと objectClass、
それに Apple 固有の属性がいくつかだけです。

**どちらを使うかは `dsconfigldap(8)` に指定できません。** サーバーを探査して
決め、その結果は Open Directory です。これは痛い目で分かりました — RFC2307
だと思い込んで書いたため、このデーモンは `ou=People` にユーザーを置き、
`opendirectoryd` は `cn=users` を見にいき、双方とも設計どおりに動いた結果、
何も見つからなかったのです。

そこで配信するのは Open Directory の配置で、これは両方を満たします。RFC2307
のクライアントは naming context 全体を 3 つの objectClass の OR
で検索しますが、これらのエントリはその 3 つを持っています。Open Directory
のクライアントは `cn=users` の下を 5 つで検索しますが、それも持っています。
エントリは 1 組、マッピングはどちらでも可、そして
`dsconfigldap -a 127.0.0.1` に他の引数は要りません。

Search Base は両方とも `%!` です。つまり**設定されていない**ということで、
`opendirectoryd` は root DSE の `namingContexts` を読んでそれを使います。
だから root DSE は飾りではなく、この仕組みが自分で自分を設定できる理由です。

`GeneratedUID` は `apple-generateduid` として配信します。値は macOS
自身がローカルレコードに使う方式 — ユーザーは
`FFFFEEEE-DDDD-CCCC-BBBB-AAAA` に uid の 16 進、グループは
`ABCDEFAB-CDEF-ABCD-EFAB-CDEF` に gid です。Open Directory
マッピングはこの属性から読み、RFC2307 マッピングは対応づけを持たないので macOS
が同じ値を導出します。どちらにせよ、ディレクトリユーザーはどの Mac 上でも同じ
UUID を持ち、それはローカルアカウントだった場合と同じ値です。

## 対応状況

| | |
| --- | --- |
| Open Directory 経由のユーザー・グループ解決 | ○ |
| 列挙 (`dscl /LDAPv3/127.0.0.1 -list /Users`) | ○ |
| グループメンバーシップ | ○ |
| `sshPublicKey` および `stns-key-wrapper` による SSH 鍵 | ○ |
| launchd のソケットアクティベーション（root にならない） | ○ |
| IPv4 / IPv6 の両対応。既定で両ループバック | ○ |
| `bind_dn` によるディレクトリの閉鎖 | ○ |
| `sshd` / `su` / `sudo` のパスワード認証 | ○ `pam_stns` |
| ログインウインドウのパスワード認証 | ✕ 後述 |
| 書き込み、StartTLS、SASL | 意図的に非対応 |

## 仕組み

デーモンはディレクトリ全体をメモリに保持し、タイマーで更新します。検索は、
接続ごとに fork した子プロセスがそのスナップショットから応答します。

この 1 つの判断で、欲しい性質のほとんどが手に入ります。更新は接続と接続の間に
行われるので、クライアントが HTTP の往復を待つことはありません。ロックを一切
持たずに複数クライアントへ同時に応答できます。そして信頼できない相手が到達
できる唯一のコードである BER パーサーが、ディレクトリを書き換えられず、接続より
長生きもしないプロセスの中に収まります。

更新に失敗したときは、前のスナップショットをそのまま保持して配信し続けます。
API サーバーが一時的に落ちたからといって、ログイン中の全員の足元から
ディレクトリを消してはいけません。ただし**最初の**更新に失敗した場合は起動せず
に終了します。ディレクトリ全員について「そんなユーザーはいない」と答えるのは、
起動しないことより悪いからです。launchd が再試行します。

## インストール

```sh
brew install --build-from-source ./pkg/homebrew/ldapstns.rb
```

または手動で。必要なのは libcurl だけで、macOS に同梱されています。

```sh
git clone --recursive https://github.com/zakinko/ldapstns.git
cd ldapstns
make                              # Intel Homebrew、または手動で /usr/local
make PREFIX=$(brew --prefix)      # Apple Silicon
sudo make PREFIX=$(brew --prefix) install
```

ここでの `make` は macOS 同梱の GNU make です。`Makefile` は POSIX
の範囲で書いてあるので、どちらの make でも動きます。

## 設定

ファイルは 2 つで、分けてあるのは意図的です。`stns.conf` は API
クライアントの設定で、`stns-key-wrapper` と共有し、Linux ホストや `nss_stns`
の動いているマシンからそのままコピーできます。`ldapstns.conf` はこのデーモン
固有の設定です。

```sh
sudo mkdir -p $(brew --prefix)/etc/stns/client
sudo cp $(brew --prefix)/share/examples/ldapstns/stns.conf \
        $(brew --prefix)/etc/stns/client/stns.conf
sudo $EDITOR $(brew --prefix)/etc/stns/client/stns.conf
```

`ldapstns.conf` は任意です。全設定に実用的な既定値があります。何を書いたに
せよ、起動する前に確認してください。

```sh
ldapstns -n
```

## 起動

`ldapstns` は自分でバックグラウンドに回りません。macOS
においてサービスの起動と監視は launchd の仕事であり、自分で fork
して去るプログラムはその仕事を launchd から取り上げてしまいます。

```sh
sudo cp $(brew --prefix)/share/ldapstns/jp.stns.ldapstns.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/jp.stns.ldapstns.plist
```

この job description は launchd のソケットアクティベーションを使います。ポート
389 は launchd 自身が root として、ジョブ開始前に bind し、その descriptor
を渡してきます。だからこの plist は非特権の `UserName` を指定でき、**デーモンは
一瞬たりとも root になりません**。それ以外の方法（`sudo brew services start
ldapstns` や手動起動）では、root で自分で bind してから `ldapstns.conf`
のユーザーへ降り、降りられたことを検証します。

言いたいことはすべて unified log に出ます。

```sh
log stream --predicate 'process == "ldapstns"'
```

## Open Directory を向ける

```sh
sudo dsconfigldap -a 127.0.0.1
```

Search Base もマッピングもスキーマファイルも要りません。確認は、まずノードを
直接、次に他のすべてが使う検索ポリシー経由で。

```sh
dscl /LDAPv3/127.0.0.1 -read /Users/alice
dscl /LDAPv3/127.0.0.1 -list /Groups
id alice
dscacheutil -q user -a name alice
```

`opendirectoryd` はかなり強くキャッシュします。何かを変えたら:

```sh
sudo dscacheutil -flushcache
sudo killall -HUP opendirectoryd
```

全部元に戻すには `sudo dsconfigldap -r 127.0.0.1`。

## SSH 鍵

上記とは無関係で、実際のところ多くの STNS 運用で一番重要な部分です。`sshd`
はコマンドを実行して出力を読むだけなので、Open Directory は関係ありません。

```text
AuthorizedKeysCommand     /usr/local/bin/stns-key-wrapper
AuthorizedKeysCommandUser nobody
```

これは `nss_stns` と `ypstns` がインストールするのと同じプログラムです。どの
システムでも動かせるので
`external/bsd/libstns` に置いてあります。

鍵は各ユーザーエントリの `sshPublicKey` としても配信するので、LDAP
から直接読む仕組みにも対応できます。

## 配信しないもの、とその理由

**パスワードハッシュ。** `expose_password` を設定しない限り `userPassword`
は出しません。そして `bind_dn` なしでそれを設定した場合、デーモンは起動を拒否
します。ループバックのソケットはマシン上の全プロセスから到達できます。そこで
crypt ハッシュを匿名クライアントに配るのは、手順が増えただけの
world-readable な shadow ファイルです。

`bind_dn` があっても、たいていは割に合いません。**ここでのパスワード認証の経路は
Open Directory ではなく `pam_stns` です。** 頼る前に知っておくべき分かれ目が
あります。

| | |
| --- | --- |
| `sshd` / `su` / `sudo` | PAM を通るので `pam_stns` が答える |
| ログインウインドウ | Open Directory 認証（Password Server と Kerberos を試す。どちらもこのデーモンは話さない） |

つまりこの構成のディレクトリユーザーは、**ssh では入れて画面からは入れません**。
画面が必要ならアカウントはローカルにし、STNS には鍵だけ供給させてください。
`pam_stns(8)` を参照。

ハッシュがもう半分の話です。macOS の `crypt(3)` は SHA-512 crypt も bcrypt も
読めず、しかもそう言いません（`$6$salt$…` を渡すと `$6` を 2 文字ソルトと解釈して
それらしい DES ハッシュを返します）。そのため `pam_stns` は自前の SHA-crypt を
持ち、公開ベクタで検証しています。

**書き込み。** add、modify、delete、modifyDN、compare は未実装です。認識できない
操作には notice of disconnection を返します。

**StartTLS** をはじめ拡張操作はすべて `unwillingToPerform` で拒否します。この
デーモンはループバックで待ち受けており、トランスポートを守るべきネットワークが
そもそも存在しません。中途半端なネゴシエーションは正直な「いいえ」より悪いです。

**SASL** は `authMethodNotSupported` で拒否します。simple bind のみです。

それでも他のローカルプロセスからディレクトリを閉じたい場合は `bind_dn` と
`bind_password` を設定し、同じ組を Directory Utility の *LDAPv3 → 編集 →
接続時に認証を使用* に与えてください。

## テスト

```sh
make test              # BER コーデック、DN 比較、フィルタマッチ
make asan              # 同じものを AddressSanitizer と UBSan で
make integration       # 実物のデーモンを ldapsearch(1) で叩く
make ident             # サンプル設定の ident 行が git archive で展開されるか
```

重要なのは `make integration` です。モックの STNS サーバーに対してデーモンを
起動し、**OpenLDAP 自身の `ldapsearch(1)`** に、返ってきたものが LDAP
かどうかを判定させます。macOS が `RFC2307.plist` から組み立てるのとまったく同じ
フィルタも含みます。このデーモンのすることはすべて、テストスイートでは代役の
立てられないクライアントに理解されるためのものであり、`ldapsearch`
は入手できる中で最もそれに近いものです。root は不要で、何もインストールしません。

「他の場所でしか壊れない」ものも見ています。検証が必要な証明書での **HTTPS**
取得（検証に失敗したら起動しないことも）、更新タイマーが実際に発火すること、API
サーバーが落ちても最後の正常なスナップショットを配信し続けること、同時 8
クライアント、そして **SSH 鍵 10 本・うち 1 本は 768 文字**のユーザー。
「1 行はこのくらい」という思い込みを超えた鍵こそが切り詰められて返ってくる鍵で、
切り詰められた鍵とは「1 人だけ黙ってログインできなくなる」ことだからです。

## ライセンス

BSD-2-Clause です。`LICENSE` を参照してください。

## 関連

| | |
| --- | --- |
| `external/bsd/libstns` | この下にある STNS API クライアント。vendor 済み |
| [nss_stns](https://github.com/zakinko/nss_stns) | NetBSD・FreeBSD・DragonFly 向け。`nsswitch(5)` モジュール |
| [ypstns](https://github.com/zakinko/ypstns) | OpenBSD 向け。YP サーバー |
