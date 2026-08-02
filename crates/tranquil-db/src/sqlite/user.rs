use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{
    Database, Sqlite, SqlitePool,
    encode::{Encode, IsNull},
    error::BoxDynError,
    types::Type,
};
use tranquil_types::{AtIdentifier, Did, Handle, Jti, PasswordHash, TokenId};
use uuid::Uuid;

use super::col;
use super::{column, legacy_column, opt_column};
use tranquil_db_traits::{
    AccountSearchResult, AccountType, ChannelVerificationStatus, CommsChannel, DbError,
    DidWebOverrides, NotificationPrefs, OAuthTokenWithUser, PasswordResetResult, SsoProviderType,
    StoredBackupCode, StoredPasskey, TotpRecord, TotpRecordState, User2faStatus, UserAuthInfo,
    UserCommsPrefs, UserConfirmSignup, UserDidWebInfo, UserEmailInfo, UserForDeletion,
    UserForDidDoc, UserForDidDocBuild, UserForPasskeyRecovery, UserForPasskeySetup,
    UserForRecovery, UserForVerification, UserIdAndHandle, UserIdAndPasswordHash,
    UserIdHandleEmail, UserInfoForAuth, UserKeyInfo, UserKeyWithId, UserLegacyLoginPref,
    UserLoginCheck, UserLoginFull, UserLoginInfo, UserPasswordInfo, UserRepository,
    UserResendVerification, UserResetCodeInfo, UserRow, UserSessionInfo, UserStatus,
    UserVerificationInfo, UserWithKey, WebauthnChallengeType,
};

pub struct SqliteUserRepository {
    pool: SqlitePool,
}

struct OwnedSqliteArg<T>(T);

impl<'q, T> Encode<'q, Sqlite> for OwnedSqliteArg<T>
where
    T: Clone + Encode<'q, Sqlite>,
{
    fn encode(
        self,
        buf: &mut <Sqlite as Database>::ArgumentBuffer<'q>,
    ) -> Result<IsNull, BoxDynError> {
        self.0.encode(buf)
    }

    fn encode_by_ref(
        &self,
        buf: &mut <Sqlite as Database>::ArgumentBuffer<'q>,
    ) -> Result<IsNull, BoxDynError> {
        self.0.clone().encode(buf)
    }

    fn size_hint(&self) -> usize {
        self.0.size_hint()
    }
}

impl<T> Type<Sqlite> for OwnedSqliteArg<T>
where
    T: Type<Sqlite>,
{
    fn type_info() -> <Sqlite as Database>::TypeInfo {
        T::type_info()
    }

    fn compatible(ty: &<Sqlite as Database>::TypeInfo) -> bool {
        T::compatible(ty)
    }
}

// `OwnedSqliteArg` always encodes its cloned value into owned SQLite argument
// storage, so the reference used by SQLx's generated query only exists while
// the macro is constructing that storage.
unsafe fn sqlite_static_ref<T>(value: &T) -> &'static T {
    unsafe { std::mem::transmute(value) }
}

macro_rules! sqlite_query {
    ($sql:expr $(,)?) => { sqlx::query($sql) };
    ($sql:expr, $($arg:expr),+ $(,)?) => {{
        let mut query = sqlx::query($sql);
        $(query = query.bind($arg);)*
        query
    }};
}

macro_rules! sqlite_query_unchecked {
    ($sql:expr $(,)?) => {{ sqlx::query_unchecked!($sql) }};
    ($sql:expr, $a:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        sqlx::query_unchecked!($sql, *a)
    }};
    ($sql:expr, $a:expr, $b:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        sqlx::query_unchecked!($sql, *a, *b)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        sqlx::query_unchecked!($sql, *a, *b, *c)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        sqlx::query_unchecked!($sql, *a, *b, *c, *d)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        let e = OwnedSqliteArg(($e).to_owned());
        let e: &'static _ = unsafe { sqlite_static_ref(&e) };
        sqlx::query_unchecked!($sql, *a, *b, *c, *d, *e)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        let e = OwnedSqliteArg(($e).to_owned());
        let e: &'static _ = unsafe { sqlite_static_ref(&e) };
        let f = OwnedSqliteArg(($f).to_owned());
        let f: &'static _ = unsafe { sqlite_static_ref(&f) };
        sqlx::query_unchecked!($sql, *a, *b, *c, *d, *e, *f)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        let e = OwnedSqliteArg(($e).to_owned());
        let e: &'static _ = unsafe { sqlite_static_ref(&e) };
        let f = OwnedSqliteArg(($f).to_owned());
        let f: &'static _ = unsafe { sqlite_static_ref(&f) };
        let g = OwnedSqliteArg(($g).to_owned());
        let g: &'static _ = unsafe { sqlite_static_ref(&g) };
        sqlx::query_unchecked!($sql, *a, *b, *c, *d, *e, *f, *g)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        let e = OwnedSqliteArg(($e).to_owned());
        let e: &'static _ = unsafe { sqlite_static_ref(&e) };
        let f = OwnedSqliteArg(($f).to_owned());
        let f: &'static _ = unsafe { sqlite_static_ref(&f) };
        let g = OwnedSqliteArg(($g).to_owned());
        let g: &'static _ = unsafe { sqlite_static_ref(&g) };
        let h = OwnedSqliteArg(($h).to_owned());
        let h: &'static _ = unsafe { sqlite_static_ref(&h) };
        sqlx::query_unchecked!($sql, *a, *b, *c, *d, *e, *f, *g, *h)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        let e = OwnedSqliteArg(($e).to_owned());
        let e: &'static _ = unsafe { sqlite_static_ref(&e) };
        let f = OwnedSqliteArg(($f).to_owned());
        let f: &'static _ = unsafe { sqlite_static_ref(&f) };
        let g = OwnedSqliteArg(($g).to_owned());
        let g: &'static _ = unsafe { sqlite_static_ref(&g) };
        let h = OwnedSqliteArg(($h).to_owned());
        let h: &'static _ = unsafe { sqlite_static_ref(&h) };
        let i = OwnedSqliteArg(($i).to_owned());
        let i: &'static _ = unsafe { sqlite_static_ref(&i) };
        sqlx::query_unchecked!($sql, *a, *b, *c, *d, *e, *f, *g, *h, *i)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        let e = OwnedSqliteArg(($e).to_owned());
        let e: &'static _ = unsafe { sqlite_static_ref(&e) };
        let f = OwnedSqliteArg(($f).to_owned());
        let f: &'static _ = unsafe { sqlite_static_ref(&f) };
        let g = OwnedSqliteArg(($g).to_owned());
        let g: &'static _ = unsafe { sqlite_static_ref(&g) };
        let h = OwnedSqliteArg(($h).to_owned());
        let h: &'static _ = unsafe { sqlite_static_ref(&h) };
        let i = OwnedSqliteArg(($i).to_owned());
        let i: &'static _ = unsafe { sqlite_static_ref(&i) };
        let j = OwnedSqliteArg(($j).to_owned());
        let j: &'static _ = unsafe { sqlite_static_ref(&j) };
        sqlx::query_unchecked!($sql, *a, *b, *c, *d, *e, *f, *g, *h, *i, *j)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr, $k:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        let e = OwnedSqliteArg(($e).to_owned());
        let e: &'static _ = unsafe { sqlite_static_ref(&e) };
        let f = OwnedSqliteArg(($f).to_owned());
        let f: &'static _ = unsafe { sqlite_static_ref(&f) };
        let g = OwnedSqliteArg(($g).to_owned());
        let g: &'static _ = unsafe { sqlite_static_ref(&g) };
        let h = OwnedSqliteArg(($h).to_owned());
        let h: &'static _ = unsafe { sqlite_static_ref(&h) };
        let i = OwnedSqliteArg(($i).to_owned());
        let i: &'static _ = unsafe { sqlite_static_ref(&i) };
        let j = OwnedSqliteArg(($j).to_owned());
        let j: &'static _ = unsafe { sqlite_static_ref(&j) };
        let k = OwnedSqliteArg(($k).to_owned());
        let k: &'static _ = unsafe { sqlite_static_ref(&k) };
        sqlx::query_unchecked!($sql, *a, *b, *c, *d, *e, *f, *g, *h, *i, *j, *k)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr, $k:expr, $l:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        let e = OwnedSqliteArg(($e).to_owned());
        let e: &'static _ = unsafe { sqlite_static_ref(&e) };
        let f = OwnedSqliteArg(($f).to_owned());
        let f: &'static _ = unsafe { sqlite_static_ref(&f) };
        let g = OwnedSqliteArg(($g).to_owned());
        let g: &'static _ = unsafe { sqlite_static_ref(&g) };
        let h = OwnedSqliteArg(($h).to_owned());
        let h: &'static _ = unsafe { sqlite_static_ref(&h) };
        let i = OwnedSqliteArg(($i).to_owned());
        let i: &'static _ = unsafe { sqlite_static_ref(&i) };
        let j = OwnedSqliteArg(($j).to_owned());
        let j: &'static _ = unsafe { sqlite_static_ref(&j) };
        let k = OwnedSqliteArg(($k).to_owned());
        let k: &'static _ = unsafe { sqlite_static_ref(&k) };
        let l = OwnedSqliteArg(($l).to_owned());
        let l: &'static _ = unsafe { sqlite_static_ref(&l) };
        sqlx::query_unchecked!($sql, *a, *b, *c, *d, *e, *f, *g, *h, *i, *j, *k, *l)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr, $k:expr, $l:expr, $m:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        let e = OwnedSqliteArg(($e).to_owned());
        let e: &'static _ = unsafe { sqlite_static_ref(&e) };
        let f = OwnedSqliteArg(($f).to_owned());
        let f: &'static _ = unsafe { sqlite_static_ref(&f) };
        let g = OwnedSqliteArg(($g).to_owned());
        let g: &'static _ = unsafe { sqlite_static_ref(&g) };
        let h = OwnedSqliteArg(($h).to_owned());
        let h: &'static _ = unsafe { sqlite_static_ref(&h) };
        let i = OwnedSqliteArg(($i).to_owned());
        let i: &'static _ = unsafe { sqlite_static_ref(&i) };
        let j = OwnedSqliteArg(($j).to_owned());
        let j: &'static _ = unsafe { sqlite_static_ref(&j) };
        let k = OwnedSqliteArg(($k).to_owned());
        let k: &'static _ = unsafe { sqlite_static_ref(&k) };
        let l = OwnedSqliteArg(($l).to_owned());
        let l: &'static _ = unsafe { sqlite_static_ref(&l) };
        let m = OwnedSqliteArg(($m).to_owned());
        let m: &'static _ = unsafe { sqlite_static_ref(&m) };
        sqlx::query_unchecked!($sql, *a, *b, *c, *d, *e, *f, *g, *h, *i, *j, *k, *l, *m)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr, $k:expr, $l:expr, $m:expr, $n:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        let e = OwnedSqliteArg(($e).to_owned());
        let e: &'static _ = unsafe { sqlite_static_ref(&e) };
        let f = OwnedSqliteArg(($f).to_owned());
        let f: &'static _ = unsafe { sqlite_static_ref(&f) };
        let g = OwnedSqliteArg(($g).to_owned());
        let g: &'static _ = unsafe { sqlite_static_ref(&g) };
        let h = OwnedSqliteArg(($h).to_owned());
        let h: &'static _ = unsafe { sqlite_static_ref(&h) };
        let i = OwnedSqliteArg(($i).to_owned());
        let i: &'static _ = unsafe { sqlite_static_ref(&i) };
        let j = OwnedSqliteArg(($j).to_owned());
        let j: &'static _ = unsafe { sqlite_static_ref(&j) };
        let k = OwnedSqliteArg(($k).to_owned());
        let k: &'static _ = unsafe { sqlite_static_ref(&k) };
        let l = OwnedSqliteArg(($l).to_owned());
        let l: &'static _ = unsafe { sqlite_static_ref(&l) };
        let m = OwnedSqliteArg(($m).to_owned());
        let m: &'static _ = unsafe { sqlite_static_ref(&m) };
        let n = OwnedSqliteArg(($n).to_owned());
        let n: &'static _ = unsafe { sqlite_static_ref(&n) };
        sqlx::query_unchecked!($sql, *a, *b, *c, *d, *e, *f, *g, *h, *i, *j, *k, *l, *m, *n)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr, $k:expr, $l:expr, $m:expr, $n:expr, $o:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        let e = OwnedSqliteArg(($e).to_owned());
        let e: &'static _ = unsafe { sqlite_static_ref(&e) };
        let f = OwnedSqliteArg(($f).to_owned());
        let f: &'static _ = unsafe { sqlite_static_ref(&f) };
        let g = OwnedSqliteArg(($g).to_owned());
        let g: &'static _ = unsafe { sqlite_static_ref(&g) };
        let h = OwnedSqliteArg(($h).to_owned());
        let h: &'static _ = unsafe { sqlite_static_ref(&h) };
        let i = OwnedSqliteArg(($i).to_owned());
        let i: &'static _ = unsafe { sqlite_static_ref(&i) };
        let j = OwnedSqliteArg(($j).to_owned());
        let j: &'static _ = unsafe { sqlite_static_ref(&j) };
        let k = OwnedSqliteArg(($k).to_owned());
        let k: &'static _ = unsafe { sqlite_static_ref(&k) };
        let l = OwnedSqliteArg(($l).to_owned());
        let l: &'static _ = unsafe { sqlite_static_ref(&l) };
        let m = OwnedSqliteArg(($m).to_owned());
        let m: &'static _ = unsafe { sqlite_static_ref(&m) };
        let n = OwnedSqliteArg(($n).to_owned());
        let n: &'static _ = unsafe { sqlite_static_ref(&n) };
        let o = OwnedSqliteArg(($o).to_owned());
        let o: &'static _ = unsafe { sqlite_static_ref(&o) };
        sqlx::query_unchecked!(
            $sql, *a, *b, *c, *d, *e, *f, *g, *h, *i, *j, *k, *l, *m, *n, *o
        )
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr, $k:expr, $l:expr, $m:expr, $n:expr, $o:expr, $p:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        let e = OwnedSqliteArg(($e).to_owned());
        let e: &'static _ = unsafe { sqlite_static_ref(&e) };
        let f = OwnedSqliteArg(($f).to_owned());
        let f: &'static _ = unsafe { sqlite_static_ref(&f) };
        let g = OwnedSqliteArg(($g).to_owned());
        let g: &'static _ = unsafe { sqlite_static_ref(&g) };
        let h = OwnedSqliteArg(($h).to_owned());
        let h: &'static _ = unsafe { sqlite_static_ref(&h) };
        let i = OwnedSqliteArg(($i).to_owned());
        let i: &'static _ = unsafe { sqlite_static_ref(&i) };
        let j = OwnedSqliteArg(($j).to_owned());
        let j: &'static _ = unsafe { sqlite_static_ref(&j) };
        let k = OwnedSqliteArg(($k).to_owned());
        let k: &'static _ = unsafe { sqlite_static_ref(&k) };
        let l = OwnedSqliteArg(($l).to_owned());
        let l: &'static _ = unsafe { sqlite_static_ref(&l) };
        let m = OwnedSqliteArg(($m).to_owned());
        let m: &'static _ = unsafe { sqlite_static_ref(&m) };
        let n = OwnedSqliteArg(($n).to_owned());
        let n: &'static _ = unsafe { sqlite_static_ref(&n) };
        let o = OwnedSqliteArg(($o).to_owned());
        let o: &'static _ = unsafe { sqlite_static_ref(&o) };
        let p = OwnedSqliteArg(($p).to_owned());
        let p: &'static _ = unsafe { sqlite_static_ref(&p) };
        sqlx::query_unchecked!(
            $sql, *a, *b, *c, *d, *e, *f, *g, *h, *i, *j, *k, *l, *m, *n, *o, *p
        )
    }};
}

macro_rules! sqlite_query_scalar_unchecked {
    ($sql:expr $(,)?) => {{ sqlx::query_scalar_unchecked!($sql) }};
    ($sql:expr, $a:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        sqlx::query_scalar_unchecked!($sql, *a)
    }};
    ($sql:expr, $a:expr, $b:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        sqlx::query_scalar_unchecked!($sql, *a, *b)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        sqlx::query_scalar_unchecked!($sql, *a, *b, *c)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        sqlx::query_scalar_unchecked!($sql, *a, *b, *c, *d)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        let e = OwnedSqliteArg(($e).to_owned());
        let e: &'static _ = unsafe { sqlite_static_ref(&e) };
        sqlx::query_scalar_unchecked!($sql, *a, *b, *c, *d, *e)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        let e = OwnedSqliteArg(($e).to_owned());
        let e: &'static _ = unsafe { sqlite_static_ref(&e) };
        let f = OwnedSqliteArg(($f).to_owned());
        let f: &'static _ = unsafe { sqlite_static_ref(&f) };
        sqlx::query_scalar_unchecked!($sql, *a, *b, *c, *d, *e, *f)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        let e = OwnedSqliteArg(($e).to_owned());
        let e: &'static _ = unsafe { sqlite_static_ref(&e) };
        let f = OwnedSqliteArg(($f).to_owned());
        let f: &'static _ = unsafe { sqlite_static_ref(&f) };
        let g = OwnedSqliteArg(($g).to_owned());
        let g: &'static _ = unsafe { sqlite_static_ref(&g) };
        sqlx::query_scalar_unchecked!($sql, *a, *b, *c, *d, *e, *f, *g)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        let e = OwnedSqliteArg(($e).to_owned());
        let e: &'static _ = unsafe { sqlite_static_ref(&e) };
        let f = OwnedSqliteArg(($f).to_owned());
        let f: &'static _ = unsafe { sqlite_static_ref(&f) };
        let g = OwnedSqliteArg(($g).to_owned());
        let g: &'static _ = unsafe { sqlite_static_ref(&g) };
        let h = OwnedSqliteArg(($h).to_owned());
        let h: &'static _ = unsafe { sqlite_static_ref(&h) };
        sqlx::query_scalar_unchecked!($sql, *a, *b, *c, *d, *e, *f, *g, *h)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        let e = OwnedSqliteArg(($e).to_owned());
        let e: &'static _ = unsafe { sqlite_static_ref(&e) };
        let f = OwnedSqliteArg(($f).to_owned());
        let f: &'static _ = unsafe { sqlite_static_ref(&f) };
        let g = OwnedSqliteArg(($g).to_owned());
        let g: &'static _ = unsafe { sqlite_static_ref(&g) };
        let h = OwnedSqliteArg(($h).to_owned());
        let h: &'static _ = unsafe { sqlite_static_ref(&h) };
        let i = OwnedSqliteArg(($i).to_owned());
        let i: &'static _ = unsafe { sqlite_static_ref(&i) };
        sqlx::query_scalar_unchecked!($sql, *a, *b, *c, *d, *e, *f, *g, *h, *i)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        let e = OwnedSqliteArg(($e).to_owned());
        let e: &'static _ = unsafe { sqlite_static_ref(&e) };
        let f = OwnedSqliteArg(($f).to_owned());
        let f: &'static _ = unsafe { sqlite_static_ref(&f) };
        let g = OwnedSqliteArg(($g).to_owned());
        let g: &'static _ = unsafe { sqlite_static_ref(&g) };
        let h = OwnedSqliteArg(($h).to_owned());
        let h: &'static _ = unsafe { sqlite_static_ref(&h) };
        let i = OwnedSqliteArg(($i).to_owned());
        let i: &'static _ = unsafe { sqlite_static_ref(&i) };
        let j = OwnedSqliteArg(($j).to_owned());
        let j: &'static _ = unsafe { sqlite_static_ref(&j) };
        sqlx::query_scalar_unchecked!($sql, *a, *b, *c, *d, *e, *f, *g, *h, *i, *j)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr, $k:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        let e = OwnedSqliteArg(($e).to_owned());
        let e: &'static _ = unsafe { sqlite_static_ref(&e) };
        let f = OwnedSqliteArg(($f).to_owned());
        let f: &'static _ = unsafe { sqlite_static_ref(&f) };
        let g = OwnedSqliteArg(($g).to_owned());
        let g: &'static _ = unsafe { sqlite_static_ref(&g) };
        let h = OwnedSqliteArg(($h).to_owned());
        let h: &'static _ = unsafe { sqlite_static_ref(&h) };
        let i = OwnedSqliteArg(($i).to_owned());
        let i: &'static _ = unsafe { sqlite_static_ref(&i) };
        let j = OwnedSqliteArg(($j).to_owned());
        let j: &'static _ = unsafe { sqlite_static_ref(&j) };
        let k = OwnedSqliteArg(($k).to_owned());
        let k: &'static _ = unsafe { sqlite_static_ref(&k) };
        sqlx::query_scalar_unchecked!($sql, *a, *b, *c, *d, *e, *f, *g, *h, *i, *j, *k)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr, $k:expr, $l:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        let e = OwnedSqliteArg(($e).to_owned());
        let e: &'static _ = unsafe { sqlite_static_ref(&e) };
        let f = OwnedSqliteArg(($f).to_owned());
        let f: &'static _ = unsafe { sqlite_static_ref(&f) };
        let g = OwnedSqliteArg(($g).to_owned());
        let g: &'static _ = unsafe { sqlite_static_ref(&g) };
        let h = OwnedSqliteArg(($h).to_owned());
        let h: &'static _ = unsafe { sqlite_static_ref(&h) };
        let i = OwnedSqliteArg(($i).to_owned());
        let i: &'static _ = unsafe { sqlite_static_ref(&i) };
        let j = OwnedSqliteArg(($j).to_owned());
        let j: &'static _ = unsafe { sqlite_static_ref(&j) };
        let k = OwnedSqliteArg(($k).to_owned());
        let k: &'static _ = unsafe { sqlite_static_ref(&k) };
        let l = OwnedSqliteArg(($l).to_owned());
        let l: &'static _ = unsafe { sqlite_static_ref(&l) };
        sqlx::query_scalar_unchecked!($sql, *a, *b, *c, *d, *e, *f, *g, *h, *i, *j, *k, *l)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr, $k:expr, $l:expr, $m:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        let e = OwnedSqliteArg(($e).to_owned());
        let e: &'static _ = unsafe { sqlite_static_ref(&e) };
        let f = OwnedSqliteArg(($f).to_owned());
        let f: &'static _ = unsafe { sqlite_static_ref(&f) };
        let g = OwnedSqliteArg(($g).to_owned());
        let g: &'static _ = unsafe { sqlite_static_ref(&g) };
        let h = OwnedSqliteArg(($h).to_owned());
        let h: &'static _ = unsafe { sqlite_static_ref(&h) };
        let i = OwnedSqliteArg(($i).to_owned());
        let i: &'static _ = unsafe { sqlite_static_ref(&i) };
        let j = OwnedSqliteArg(($j).to_owned());
        let j: &'static _ = unsafe { sqlite_static_ref(&j) };
        let k = OwnedSqliteArg(($k).to_owned());
        let k: &'static _ = unsafe { sqlite_static_ref(&k) };
        let l = OwnedSqliteArg(($l).to_owned());
        let l: &'static _ = unsafe { sqlite_static_ref(&l) };
        let m = OwnedSqliteArg(($m).to_owned());
        let m: &'static _ = unsafe { sqlite_static_ref(&m) };
        sqlx::query_scalar_unchecked!($sql, *a, *b, *c, *d, *e, *f, *g, *h, *i, *j, *k, *l, *m)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr, $k:expr, $l:expr, $m:expr, $n:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        let e = OwnedSqliteArg(($e).to_owned());
        let e: &'static _ = unsafe { sqlite_static_ref(&e) };
        let f = OwnedSqliteArg(($f).to_owned());
        let f: &'static _ = unsafe { sqlite_static_ref(&f) };
        let g = OwnedSqliteArg(($g).to_owned());
        let g: &'static _ = unsafe { sqlite_static_ref(&g) };
        let h = OwnedSqliteArg(($h).to_owned());
        let h: &'static _ = unsafe { sqlite_static_ref(&h) };
        let i = OwnedSqliteArg(($i).to_owned());
        let i: &'static _ = unsafe { sqlite_static_ref(&i) };
        let j = OwnedSqliteArg(($j).to_owned());
        let j: &'static _ = unsafe { sqlite_static_ref(&j) };
        let k = OwnedSqliteArg(($k).to_owned());
        let k: &'static _ = unsafe { sqlite_static_ref(&k) };
        let l = OwnedSqliteArg(($l).to_owned());
        let l: &'static _ = unsafe { sqlite_static_ref(&l) };
        let m = OwnedSqliteArg(($m).to_owned());
        let m: &'static _ = unsafe { sqlite_static_ref(&m) };
        let n = OwnedSqliteArg(($n).to_owned());
        let n: &'static _ = unsafe { sqlite_static_ref(&n) };
        sqlx::query_scalar_unchecked!($sql, *a, *b, *c, *d, *e, *f, *g, *h, *i, *j, *k, *l, *m, *n)
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr, $k:expr, $l:expr, $m:expr, $n:expr, $o:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        let e = OwnedSqliteArg(($e).to_owned());
        let e: &'static _ = unsafe { sqlite_static_ref(&e) };
        let f = OwnedSqliteArg(($f).to_owned());
        let f: &'static _ = unsafe { sqlite_static_ref(&f) };
        let g = OwnedSqliteArg(($g).to_owned());
        let g: &'static _ = unsafe { sqlite_static_ref(&g) };
        let h = OwnedSqliteArg(($h).to_owned());
        let h: &'static _ = unsafe { sqlite_static_ref(&h) };
        let i = OwnedSqliteArg(($i).to_owned());
        let i: &'static _ = unsafe { sqlite_static_ref(&i) };
        let j = OwnedSqliteArg(($j).to_owned());
        let j: &'static _ = unsafe { sqlite_static_ref(&j) };
        let k = OwnedSqliteArg(($k).to_owned());
        let k: &'static _ = unsafe { sqlite_static_ref(&k) };
        let l = OwnedSqliteArg(($l).to_owned());
        let l: &'static _ = unsafe { sqlite_static_ref(&l) };
        let m = OwnedSqliteArg(($m).to_owned());
        let m: &'static _ = unsafe { sqlite_static_ref(&m) };
        let n = OwnedSqliteArg(($n).to_owned());
        let n: &'static _ = unsafe { sqlite_static_ref(&n) };
        let o = OwnedSqliteArg(($o).to_owned());
        let o: &'static _ = unsafe { sqlite_static_ref(&o) };
        sqlx::query_scalar_unchecked!(
            $sql, *a, *b, *c, *d, *e, *f, *g, *h, *i, *j, *k, *l, *m, *n, *o
        )
    }};
    ($sql:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr, $k:expr, $l:expr, $m:expr, $n:expr, $o:expr, $p:expr $(,)?) => {{
        let a = OwnedSqliteArg(($a).to_owned());
        let a: &'static _ = unsafe { sqlite_static_ref(&a) };
        let b = OwnedSqliteArg(($b).to_owned());
        let b: &'static _ = unsafe { sqlite_static_ref(&b) };
        let c = OwnedSqliteArg(($c).to_owned());
        let c: &'static _ = unsafe { sqlite_static_ref(&c) };
        let d = OwnedSqliteArg(($d).to_owned());
        let d: &'static _ = unsafe { sqlite_static_ref(&d) };
        let e = OwnedSqliteArg(($e).to_owned());
        let e: &'static _ = unsafe { sqlite_static_ref(&e) };
        let f = OwnedSqliteArg(($f).to_owned());
        let f: &'static _ = unsafe { sqlite_static_ref(&f) };
        let g = OwnedSqliteArg(($g).to_owned());
        let g: &'static _ = unsafe { sqlite_static_ref(&g) };
        let h = OwnedSqliteArg(($h).to_owned());
        let h: &'static _ = unsafe { sqlite_static_ref(&h) };
        let i = OwnedSqliteArg(($i).to_owned());
        let i: &'static _ = unsafe { sqlite_static_ref(&i) };
        let j = OwnedSqliteArg(($j).to_owned());
        let j: &'static _ = unsafe { sqlite_static_ref(&j) };
        let k = OwnedSqliteArg(($k).to_owned());
        let k: &'static _ = unsafe { sqlite_static_ref(&k) };
        let l = OwnedSqliteArg(($l).to_owned());
        let l: &'static _ = unsafe { sqlite_static_ref(&l) };
        let m = OwnedSqliteArg(($m).to_owned());
        let m: &'static _ = unsafe { sqlite_static_ref(&m) };
        let n = OwnedSqliteArg(($n).to_owned());
        let n: &'static _ = unsafe { sqlite_static_ref(&n) };
        let o = OwnedSqliteArg(($o).to_owned());
        let o: &'static _ = unsafe { sqlite_static_ref(&o) };
        let p = OwnedSqliteArg(($p).to_owned());
        let p: &'static _ = unsafe { sqlite_static_ref(&p) };
        sqlx::query_scalar_unchecked!(
            $sql, *a, *b, *c, *d, *e, *f, *g, *h, *i, *j, *k, *l, *m, *n, *o, *p
        )
    }};
}

fn parse_timestamp(value: String) -> Result<DateTime<Utc>, DbError> {
    DateTime::parse_from_rfc3339(&value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| DbError::Other(format!("invalid SQLite timestamp: {error}")))
}

fn parse_optional_timestamp(value: Option<String>) -> Result<Option<DateTime<Utc>>, DbError> {
    value.map(parse_timestamp).transpose()
}

fn parse_uuid(value: Vec<u8>) -> Result<Uuid, DbError> {
    Uuid::from_slice(&value)
        .map_err(|error| DbError::Other(format!("invalid SQLite UUID: {error}")))
}

fn parse_i32(value: i64) -> Result<i32, DbError> {
    value
        .try_into()
        .map_err(|error| DbError::Other(format!("SQLite integer out of range: {error}")))
}

fn query_str(value: &str) -> String {
    value.to_owned()
}

fn query_arg<T>(value: T) -> T {
    value
}

fn parse_json<T: serde::de::DeserializeOwned>(value: String) -> Result<T, DbError> {
    serde_json::from_str(&value)
        .map_err(|error| DbError::Other(format!("invalid SQLite JSON: {error}")))
}

fn parse_optional_json<T: serde::de::DeserializeOwned>(
    value: Option<String>,
) -> Result<Option<T>, DbError> {
    value.map(parse_json).transpose()
}

impl SqliteUserRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

pub(crate) fn map_sqlite_error(e: sqlx::Error) -> DbError {
    match e {
        sqlx::Error::RowNotFound => DbError::NotFound,
        sqlx::Error::Database(db_err) => {
            let msg = db_err.message().to_string();
            if db_err.is_unique_violation() || db_err.is_foreign_key_violation() {
                DbError::Constraint(msg)
            } else {
                DbError::Query(msg)
            }
        }
        sqlx::Error::PoolTimedOut => DbError::Connection("Pool timed out".into()),
        _ => DbError::Other(e.to_string()),
    }
}

async fn consume_invite_code(
    conn: &mut sqlx::SqliteConnection,
    code: &str,
    user_id: Uuid,
) -> Result<(), tranquil_db_traits::CreateAccountError> {
    let map_err = |e: sqlx::Error| tranquil_db_traits::CreateAccountError::Database(e.to_string());

    let decremented = sqlite_query!(
        "UPDATE invite_codes SET available_uses = available_uses - 1 WHERE code = $1 AND available_uses > 0 AND COALESCE(disabled, false) = false",
        code
    )
    .execute(&mut *conn)
    .await
    .map_err(map_err)?
    .rows_affected();

    if decremented == 0 {
        return Err(tranquil_db_traits::CreateAccountError::InviteCodeUnavailable);
    }

    sqlite_query!(
        "INSERT INTO invite_code_uses (code, used_by_user) VALUES ($1, $2)",
        code,
        user_id
    )
    .execute(&mut *conn)
    .await
    .map_err(map_err)?;

    Ok(())
}

#[async_trait]
impl UserRepository for SqliteUserRepository {
    async fn get_by_did(&self, did: &Did) -> Result<Option<UserRow>, DbError> {
        let row = sqlite_query_unchecked!(
            r#"SELECT id, did, handle, email, created_at, deactivated_at, takedown_ref, is_admin, inbound_migration
               FROM users WHERE did = $1"#,
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            Ok(UserRow {
                id: parse_uuid(r.id.ok_or(DbError::NotFound)?)?,
                did: column(r.did, col::USERS_DID)?,
                handle: column(r.handle, col::USERS_HANDLE)?,
                email: r.email,
                created_at: parse_timestamp(r.created_at)?,
                deactivated_at: parse_optional_timestamp(r.deactivated_at)?,
                takedown_ref: r.takedown_ref,
                is_admin: r.is_admin != 0,
                inbound_migration: r.inbound_migration != 0,
            })
        })
        .transpose()
    }

    async fn get_by_handle(&self, handle: &Handle) -> Result<Option<UserRow>, DbError> {
        let row = sqlite_query_unchecked!(
            r#"SELECT id, did, handle, email, created_at, deactivated_at, takedown_ref, is_admin, inbound_migration
               FROM users WHERE handle = $1"#,
            query_arg(handle.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            Ok(UserRow {
                id: parse_uuid(r.id.ok_or(DbError::NotFound)?)?,
                did: column(r.did, col::USERS_DID)?,
                handle: column(r.handle, col::USERS_HANDLE)?,
                email: r.email,
                created_at: parse_timestamp(r.created_at)?,
                deactivated_at: parse_optional_timestamp(r.deactivated_at)?,
                takedown_ref: r.takedown_ref,
                is_admin: r.is_admin != 0,
                inbound_migration: r.inbound_migration != 0,
            })
        })
        .transpose()
    }

    async fn get_with_key_by_did(&self, did: &Did) -> Result<Option<UserWithKey>, DbError> {
        let row = sqlite_query_unchecked!(
            r#"SELECT u.id, u.did, u.handle, u.email, u.deactivated_at, u.takedown_ref, u.is_admin,
                      k.key_bytes, k.encryption_version
               FROM users u
               JOIN user_keys k ON u.id = k.user_id
               WHERE u.did = $1"#,
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            Ok(UserWithKey {
                id: parse_uuid(r.id.ok_or(DbError::NotFound)?)?,
                did: column(r.did, col::USERS_DID)?,
                handle: column(r.handle, col::USERS_HANDLE)?,
                email: r.email,
                deactivated_at: parse_optional_timestamp(r.deactivated_at)?,
                takedown_ref: r.takedown_ref,
                is_admin: r.is_admin != 0,
                key_bytes: r.key_bytes,
                encryption_version: r.encryption_version.map(parse_i32).transpose()?,
            })
        })
        .transpose()
    }

    async fn get_status_by_did(&self, did: &Did) -> Result<Option<UserStatus>, DbError> {
        let row = sqlite_query_unchecked!(
            "SELECT deactivated_at, takedown_ref, is_admin FROM users WHERE did = $1",
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            Ok(UserStatus {
                deactivated_at: parse_optional_timestamp(r.deactivated_at)?,
                takedown_ref: r.takedown_ref,
                is_admin: r.is_admin != 0,
            })
        })
        .transpose()
    }

    async fn count_users(&self) -> Result<i64, DbError> {
        let row: i64 = sqlite_query_scalar_unchecked!("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlite_error)?;
        Ok(row)
    }

    async fn get_session_access_expiry(
        &self,
        did: &Did,
        access_jti: &Jti,
    ) -> Result<Option<DateTime<Utc>>, DbError> {
        let row = sqlite_query_unchecked!(
            "SELECT access_expires_at FROM session_tokens WHERE did = $1 AND access_jti = $2",
            query_arg(did.to_string()),
            access_jti.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| parse_timestamp(r.access_expires_at))
            .transpose()
    }

    async fn get_oauth_token_with_user(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<OAuthTokenWithUser>, DbError> {
        let row = sqlite_query_unchecked!(
            r#"SELECT t.did, t.expires_at, u.deactivated_at, u.takedown_ref, u.is_admin,
                      k.key_bytes as "key_bytes?", k.encryption_version as "encryption_version?"
               FROM oauth_token t
               JOIN users u ON t.did = u.did
               LEFT JOIN user_keys k ON u.id = k.user_id
               WHERE t.token_id = $1"#,
            token_id.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            Ok(OAuthTokenWithUser {
                did: column(r.did, col::OAUTH_TOKEN_DID)?,
                expires_at: parse_timestamp(r.expires_at)?,
                deactivated_at: parse_optional_timestamp(r.deactivated_at)?,
                takedown_ref: r.takedown_ref,
                is_admin: r.is_admin != 0,
                key_bytes: r.key_bytes,
                encryption_version: r.encryption_version.map(parse_i32).transpose()?,
            })
        })
        .transpose()
    }

    async fn get_user_info_by_did(&self, did: &Did) -> Result<Option<UserInfoForAuth>, DbError> {
        let row = sqlite_query_unchecked!(
            r#"SELECT u.deactivated_at, u.takedown_ref, u.is_admin,
                      k.key_bytes as "key_bytes?", k.encryption_version as "encryption_version?"
               FROM users u
               LEFT JOIN user_keys k ON u.id = k.user_id
               WHERE u.did = $1"#,
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            Ok(UserInfoForAuth {
                deactivated_at: parse_optional_timestamp(r.deactivated_at)?,
                takedown_ref: r.takedown_ref,
                is_admin: r.is_admin != 0,
                key_bytes: r.key_bytes,
                encryption_version: r.encryption_version.map(parse_i32).transpose()?,
            })
        })
        .transpose()
    }

    async fn get_any_admin_user_id(&self) -> Result<Option<Uuid>, DbError> {
        let row =
            sqlite_query_scalar_unchecked!("SELECT id FROM users WHERE is_admin = true LIMIT 1")
                .fetch_optional(&self.pool)
                .await
                .map_err(map_sqlite_error)?;
        row.flatten().map(parse_uuid).transpose()
    }

    async fn set_invites_disabled(&self, did: &Did, disabled: bool) -> Result<bool, DbError> {
        let result = sqlite_query!(
            "UPDATE users SET invites_disabled = $2 WHERE did = $1",
            query_arg(did.to_string()),
            disabled
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn search_accounts(
        &self,
        cursor_did: Option<&Did>,
        email_filter: Option<&str>,
        handle_filter: Option<&str>,
        limit: i64,
    ) -> Result<Vec<AccountSearchResult>, DbError> {
        let cursor_str = cursor_did.map(|d| d.to_string());
        let email_like = email_filter.map(|e| format!("%{e}%"));
        let handle_like = handle_filter.map(|h| format!("%{h}%"));
        let rows = sqlite_query_unchecked!(
            r#"SELECT did, handle, email, created_at, email_verified, deactivated_at, invites_disabled
               FROM users
               WHERE ($1 IS NULL OR did > $1)
                 AND ($2 IS NULL OR email LIKE $2)
                 AND ($3 IS NULL OR handle LIKE $3)
               ORDER BY did ASC
               LIMIT $4"#,
            cursor_str,
            email_like,
            handle_like,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(rows
            .into_iter()
            .filter_map(|r| {
                Some(AccountSearchResult {
                    did: legacy_column(r.did, col::USERS_DID)?,
                    handle: legacy_column(r.handle, col::USERS_HANDLE)?,
                    email: r.email,
                    created_at: parse_timestamp(r.created_at).ok()?,
                    email_verified: r.email_verified != 0,
                    deactivated_at: parse_optional_timestamp(r.deactivated_at).ok()?,
                    invites_disabled: r.invites_disabled.map(|v| v != 0),
                })
            })
            .collect())
    }

    async fn get_auth_info_by_did(&self, did: &Did) -> Result<Option<UserAuthInfo>, DbError> {
        let row = sqlite_query_unchecked!(
            r#"SELECT id, did, password_hash, deactivated_at, takedown_ref,
                      email_verified, discord_verified, telegram_verified, signal_verified
               FROM users
               WHERE did = $1"#,
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        row.map(|r| {
            Ok(UserAuthInfo {
                id: parse_uuid(r.id.ok_or(DbError::NotFound)?)?,
                did: column(r.did, col::USERS_DID)?,
                password_hash: r.password_hash.map(PasswordHash::new),
                deactivated_at: parse_optional_timestamp(r.deactivated_at)?,
                takedown_ref: r.takedown_ref,
                channel_verification: ChannelVerificationStatus::from_db_row(
                    r.email_verified != 0,
                    r.discord_verified != 0,
                    r.telegram_verified != 0,
                    r.signal_verified != 0,
                ),
            })
        })
        .transpose()
    }

    async fn get_by_email(&self, email: &str) -> Result<Option<UserForVerification>, DbError> {
        let row = sqlite_query_unchecked!(
            r#"SELECT id, did, email, email_verified
               FROM users
               WHERE LOWER(email) = $1"#,
            email
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        row.map(|r| {
            Ok(UserForVerification {
                id: parse_uuid(r.id.ok_or(DbError::NotFound)?)?,
                did: column(r.did, col::USERS_DID)?,
                email: r.email,
                email_verified: r.email_verified != 0,
            })
        })
        .transpose()
    }

    async fn get_comms_prefs(&self, user_id: Uuid) -> Result<Option<UserCommsPrefs>, DbError> {
        let row = sqlite_query_unchecked!(
            r#"SELECT email, handle, preferred_comms_channel as "preferred_channel!: CommsChannel", preferred_locale, telegram_chat_id, discord_id, signal_username
               FROM users WHERE id = $1"#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        row.map(|r| {
            Ok(UserCommsPrefs {
                email: r.email,
                handle: column(r.handle, col::USERS_HANDLE)?,
                preferred_channel: r.preferred_channel,
                preferred_locale: r.preferred_locale,
                telegram_chat_id: r.telegram_chat_id,
                discord_id: r.discord_id,
                signal_username: r.signal_username,
            })
        })
        .transpose()
    }

    async fn get_id_by_did(&self, did: &Did) -> Result<Option<Uuid>, DbError> {
        let id = sqlite_query_scalar_unchecked!(
            "SELECT id FROM users WHERE did = $1",
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        id.flatten().map(parse_uuid).transpose()
    }

    async fn get_user_key_by_id(&self, user_id: Uuid) -> Result<Option<UserKeyInfo>, DbError> {
        let row = sqlite_query_unchecked!(
            "SELECT key_bytes, encryption_version FROM user_keys WHERE user_id = $1",
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        row.map(|r| {
            Ok(UserKeyInfo {
                key_bytes: r.key_bytes,
                encryption_version: r.encryption_version.map(parse_i32).transpose()?,
            })
        })
        .transpose()
    }

    async fn get_id_and_handle_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserIdAndHandle>, DbError> {
        let row = sqlite_query_unchecked!(
            "SELECT id, handle FROM users WHERE did = $1",
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        row.map(|r| {
            Ok(UserIdAndHandle {
                id: parse_uuid(r.id.ok_or(DbError::NotFound)?)?,
                handle: column(r.handle, col::USERS_HANDLE)?,
            })
        })
        .transpose()
    }

    async fn get_did_web_info_by_handle(
        &self,
        handle: &Handle,
    ) -> Result<Option<UserDidWebInfo>, DbError> {
        let row = sqlite_query_unchecked!(
            "SELECT id, did, migrated_to_pds FROM users WHERE handle = $1",
            query_arg(handle.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        row.map(|r| {
            Ok(UserDidWebInfo {
                id: parse_uuid(r.id.ok_or(DbError::NotFound)?)?,
                did: column(r.did, col::USERS_DID)?,
                migrated_to_pds: r.migrated_to_pds,
            })
        })
        .transpose()
    }

    async fn get_did_web_overrides(
        &self,
        user_id: Uuid,
    ) -> Result<Option<DidWebOverrides>, DbError> {
        let row = sqlite_query_unchecked!(
            "SELECT verification_methods, also_known_as FROM did_web_overrides WHERE user_id = $1",
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        row.map(|r| {
            Ok(DidWebOverrides {
                verification_methods: parse_json(r.verification_methods)?,
                also_known_as: parse_json(r.also_known_as)?,
            })
        })
        .transpose()
    }

    async fn get_handle_by_did(&self, did: &Did) -> Result<Option<Handle>, DbError> {
        let handle = sqlite_query_scalar_unchecked!(
            "SELECT handle FROM users WHERE did = $1",
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        opt_column(handle, col::USERS_HANDLE)
    }

    async fn check_handle_exists(
        &self,
        handle: &Handle,
        exclude_user_id: Uuid,
    ) -> Result<bool, DbError> {
        let exists = sqlite_query_scalar_unchecked!(
            "SELECT EXISTS(SELECT 1 FROM users WHERE handle = $1 AND id != $2) as \"exists!\"",
            query_arg(handle.to_string()),
            exclude_user_id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(exists != 0)
    }

    async fn update_handle(&self, user_id: Uuid, handle: &Handle) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE users SET handle = $1 WHERE id = $2",
            query_arg(handle.to_string()),
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn get_user_with_key_by_did(&self, did: &Did) -> Result<Option<UserKeyWithId>, DbError> {
        let row = sqlite_query_unchecked!(
            r#"SELECT u.id, uk.key_bytes, uk.encryption_version
               FROM users u
               JOIN user_keys uk ON u.id = uk.user_id
               WHERE u.did = $1"#,
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        row.map(|r| {
            Ok(UserKeyWithId {
                id: parse_uuid(r.id.ok_or(DbError::NotFound)?)?,
                key_bytes: r.key_bytes,
                encryption_version: r.encryption_version.map(parse_i32).transpose()?,
            })
        })
        .transpose()
    }

    async fn is_account_migrated(&self, did: &Did) -> Result<bool, DbError> {
        let row = sqlite_query_unchecked!(
            r#"SELECT (migrated_to_pds IS NOT NULL AND deactivated_at IS NOT NULL) as "migrated!: bool" FROM users WHERE did = $1"#,
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(row.map(|r| r.migrated).unwrap_or(false))
    }

    async fn has_verified_comms_channel(&self, did: &Did) -> Result<bool, DbError> {
        let row = sqlite_query_unchecked!(
            r#"SELECT
                email_verified,
                discord_verified,
                telegram_verified,
                signal_verified
            FROM users
            WHERE did = $1"#,
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(row
            .map(|r| {
                r.email_verified != 0
                    || r.discord_verified != 0
                    || r.telegram_verified != 0
                    || r.signal_verified != 0
            })
            .unwrap_or(false))
    }

    async fn get_id_by_handle(&self, handle: &Handle) -> Result<Option<Uuid>, DbError> {
        let id = sqlite_query_scalar_unchecked!(
            "SELECT id FROM users WHERE handle = $1",
            query_arg(handle.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        id.flatten().map(parse_uuid).transpose()
    }

    async fn get_email_info_by_did(&self, did: &Did) -> Result<Option<UserEmailInfo>, DbError> {
        let row = sqlite_query_unchecked!(
            "SELECT id, handle, email, email_verified FROM users WHERE did = $1",
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        row.map(|r| {
            Ok(UserEmailInfo {
                id: parse_uuid(r.id.ok_or(DbError::NotFound)?)?,
                handle: column(r.handle, col::USERS_HANDLE)?,
                email: r.email,
                email_verified: r.email_verified != 0,
            })
        })
        .transpose()
    }

    async fn check_email_exists(
        &self,
        email: &str,
        exclude_user_id: Uuid,
    ) -> Result<bool, DbError> {
        let row = sqlite_query_unchecked!(
            "SELECT 1 as one FROM users WHERE LOWER(email) = $1 AND id != $2",
            email.to_lowercase(),
            exclude_user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(row.is_some())
    }

    async fn update_email(&self, user_id: Uuid, email: &str) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE users SET email = $1, email_verified = FALSE, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = $2",
            email,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn set_email_verified(&self, user_id: Uuid, verified: bool) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE users SET email_verified = $1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = $2",
            verified,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn check_email_verified_by_identifier(
        &self,
        identifier: &AtIdentifier,
    ) -> Result<Option<bool>, DbError> {
        let row = sqlite_query_scalar_unchecked!(
            "SELECT email_verified FROM users WHERE did = $1 OR email = $1 OR handle = $1",
            query_arg(identifier.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(row.map(|value| value != 0))
    }

    async fn check_channel_verified_by_did(
        &self,
        did: &Did,
        channel: CommsChannel,
    ) -> Result<Option<bool>, DbError> {
        let row = sqlite_query_unchecked!(
            r#"SELECT
                email_verified,
                discord_verified,
                telegram_verified,
                signal_verified
            FROM users
            WHERE did = $1"#,
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(row.map(|r| match channel {
            CommsChannel::Email => r.email_verified != 0,
            CommsChannel::Discord => r.discord_verified != 0,
            CommsChannel::Telegram => r.telegram_verified != 0,
            CommsChannel::Signal => r.signal_verified != 0,
        }))
    }

    async fn admin_update_email(&self, did: &Did, email: &str) -> Result<u64, DbError> {
        let result = sqlite_query!(
            "UPDATE users SET email = $1 WHERE did = $2",
            email,
            query_arg(did.to_string())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(result.rows_affected())
    }

    async fn admin_update_handle(&self, did: &Did, handle: &Handle) -> Result<u64, DbError> {
        let result = sqlite_query!(
            "UPDATE users SET handle = $1 WHERE did = $2",
            query_arg(handle.to_string()),
            query_arg(did.to_string())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(result.rows_affected())
    }

    async fn admin_update_password(
        &self,
        did: &Did,
        password_hash: &PasswordHash,
    ) -> Result<u64, DbError> {
        let result = sqlite_query!(
            "UPDATE users SET password_hash = $1 WHERE did = $2",
            query_arg(password_hash.as_str().to_owned()),
            query_arg(did.to_string())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(result.rows_affected())
    }

    async fn set_admin_status(&self, did: &Did, is_admin: bool) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE users SET is_admin = $1 WHERE did = $2",
            is_admin,
            query_arg(did.to_string())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn get_notification_prefs(
        &self,
        did: &Did,
    ) -> Result<Option<NotificationPrefs>, DbError> {
        let row = sqlite_query_unchecked!(
            r#"SELECT
                email,
                preferred_comms_channel as "preferred_channel!: CommsChannel",
                discord_id,
                discord_username,
                discord_verified,
                telegram_username,
                telegram_verified,
                telegram_chat_id,
                signal_username,
                signal_verified
            FROM users WHERE did = $1"#,
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(row.map(|r| NotificationPrefs {
            email: r.email.unwrap_or_default(),
            preferred_channel: r.preferred_channel,
            discord_id: r.discord_id,
            discord_username: r.discord_username,
            discord_verified: r.discord_verified != 0,
            telegram_username: r.telegram_username,
            telegram_verified: r.telegram_verified != 0,
            telegram_chat_id: r.telegram_chat_id,
            signal_username: r.signal_username,
            signal_verified: r.signal_verified != 0,
        }))
    }

    async fn get_id_handle_email_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserIdHandleEmail>, DbError> {
        let row = sqlite_query_unchecked!(
            "SELECT id, handle, email FROM users WHERE did = $1",
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        row.map(|r| {
            Ok(UserIdHandleEmail {
                id: parse_uuid(r.id.ok_or(DbError::NotFound)?)?,
                handle: column(r.handle, col::USERS_HANDLE)?,
                email: r.email,
            })
        })
        .transpose()
    }

    async fn update_preferred_comms_channel(
        &self,
        did: &Did,
        channel: CommsChannel,
    ) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE users SET preferred_comms_channel = $1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE did = $2",
            channel as CommsChannel,
            query_arg(did.to_string())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn clear_discord(&self, user_id: Uuid) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE users SET discord_id = NULL, discord_username = NULL, discord_verified = FALSE, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = $1",
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn clear_telegram(&self, user_id: Uuid) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE users SET telegram_username = NULL, telegram_verified = FALSE, telegram_chat_id = NULL, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = $1",
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn clear_signal(&self, user_id: Uuid) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE users SET signal_username = NULL, signal_verified = FALSE, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = $1",
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn get_verification_info(
        &self,
        did: &Did,
    ) -> Result<Option<UserVerificationInfo>, DbError> {
        let row = sqlite_query_unchecked!(
            r#"SELECT id, handle, email, email_verified, discord_verified, telegram_verified, signal_verified
               FROM users WHERE did = $1"#,
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        row.map(|r| {
            Ok(UserVerificationInfo {
                id: parse_uuid(r.id.ok_or(DbError::NotFound)?)?,
                handle: column(r.handle, col::USERS_HANDLE)?,
                email: r.email,
                channel_verification: ChannelVerificationStatus::from_db_row(
                    r.email_verified != 0,
                    r.discord_verified != 0,
                    r.telegram_verified != 0,
                    r.signal_verified != 0,
                ),
            })
        })
        .transpose()
    }

    async fn verify_email_channel(&self, user_id: Uuid, email: &str) -> Result<bool, DbError> {
        sqlite_query!(
            "UPDATE users SET email = $1, email_verified = TRUE, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = $2",
            email,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(true)
    }

    async fn verify_discord_channel(&self, user_id: Uuid, discord_id: &str) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE users SET discord_id = $1, discord_verified = TRUE, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = $2",
            discord_id,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn verify_telegram_channel(
        &self,
        user_id: Uuid,
        telegram_username: &str,
    ) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE users SET telegram_username = $1, telegram_verified = TRUE, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = $2",
            telegram_username,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn verify_signal_channel(
        &self,
        user_id: Uuid,
        signal_username: &str,
    ) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE users SET signal_username = $1, signal_verified = TRUE, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = $2",
            signal_username,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn set_email_verified_flag(&self, user_id: Uuid) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE users SET email_verified = TRUE WHERE id = $1",
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn set_discord_verified_flag(&self, user_id: Uuid) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE users SET discord_verified = TRUE WHERE id = $1",
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn set_telegram_verified_flag(&self, user_id: Uuid) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE users SET telegram_verified = TRUE WHERE id = $1",
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn set_signal_verified_flag(&self, user_id: Uuid) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE users SET signal_verified = TRUE WHERE id = $1",
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn has_totp_enabled(&self, did: &Did) -> Result<bool, DbError> {
        let row = sqlite_query_scalar_unchecked!(
            "SELECT verified FROM user_totp WHERE did = $1",
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(matches!(row, Some(value) if value != 0))
    }

    async fn has_passkeys(&self, did: &Did) -> Result<bool, DbError> {
        let count = sqlite_query_scalar_unchecked!(
            "SELECT COUNT(*) as count FROM passkeys WHERE did = $1",
            query_arg(did.to_string())
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(count > 0)
    }

    async fn get_password_hash_by_did(&self, did: &Did) -> Result<Option<PasswordHash>, DbError> {
        let row = sqlite_query_scalar_unchecked!(
            "SELECT password_hash FROM users WHERE did = $1",
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(row.flatten().map(PasswordHash::new))
    }

    async fn get_passkeys_for_user(&self, did: &Did) -> Result<Vec<StoredPasskey>, DbError> {
        let rows = sqlite_query_unchecked!(
            r#"SELECT id, did, credential_id, public_key, sign_count, created_at, last_used,
                      friendly_name, aaguid, transports
               FROM passkeys WHERE did = $1 ORDER BY created_at DESC"#,
            query_arg(did.to_string())
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        rows.into_iter()
            .map(|r| {
                Ok(StoredPasskey {
                    id: parse_uuid(r.id.ok_or(DbError::NotFound)?)?,
                    did: column(r.did, col::PASSKEYS_DID)?,
                    credential_id: r.credential_id,
                    public_key: r.public_key,
                    sign_count: parse_i32(r.sign_count)?,
                    created_at: parse_timestamp(r.created_at)?,
                    last_used: parse_optional_timestamp(r.last_used)?,
                    friendly_name: r.friendly_name,
                    aaguid: r.aaguid,
                    transports: parse_optional_json(r.transports)?,
                })
            })
            .collect()
    }

    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<StoredPasskey>, DbError> {
        let row = sqlite_query_unchecked!(
            r#"SELECT id, did, credential_id, public_key, sign_count, created_at, last_used,
                      friendly_name, aaguid, transports
               FROM passkeys WHERE credential_id = $1"#,
            credential_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            Ok(StoredPasskey {
                id: parse_uuid(r.id.ok_or(DbError::NotFound)?)?,
                did: column(r.did, col::PASSKEYS_DID)?,
                credential_id: r.credential_id,
                public_key: r.public_key,
                sign_count: parse_i32(r.sign_count)?,
                created_at: parse_timestamp(r.created_at)?,
                last_used: parse_optional_timestamp(r.last_used)?,
                friendly_name: r.friendly_name,
                aaguid: r.aaguid,
                transports: parse_optional_json(r.transports)?,
            })
        })
        .transpose()
    }

    async fn save_passkey(
        &self,
        did: &Did,
        credential_id: &[u8],
        public_key: &[u8],
        friendly_name: Option<&str>,
    ) -> Result<Uuid, DbError> {
        let id = Uuid::new_v4();
        let aaguid: Option<Vec<u8>> = None;
        sqlite_query!(r#"INSERT INTO passkeys (id, did, credential_id, public_key, sign_count, friendly_name, aaguid)
               VALUES ($1, $2, $3, $4, 0, $5, $6)"#,
            id,
            query_arg(did.to_string()),
            credential_id,
            public_key,
            friendly_name,
            aaguid,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(id)
    }

    async fn update_passkey_counter(
        &self,
        credential_id: &[u8],
        new_counter: i32,
    ) -> Result<bool, DbError> {
        let stored = self.get_passkey_by_credential_id(credential_id).await?;
        let Some(stored) = stored else {
            return Err(DbError::NotFound);
        };

        if new_counter > 0 && new_counter <= stored.sign_count {
            return Ok(false);
        }

        sqlite_query!(
            "UPDATE passkeys SET sign_count = $1, last_used = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE credential_id = $2",
            new_counter,
            credential_id,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(true)
    }

    async fn delete_passkey(&self, id: Uuid, did: &Did) -> Result<bool, DbError> {
        let result = sqlite_query!(
            "DELETE FROM passkeys WHERE id = $1 AND did = $2",
            id,
            query_arg(did.to_string())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(result.rows_affected() > 0)
    }

    async fn update_passkey_name(&self, id: Uuid, did: &Did, name: &str) -> Result<bool, DbError> {
        let result = sqlite_query!(
            "UPDATE passkeys SET friendly_name = $1 WHERE id = $2 AND did = $3",
            name,
            id,
            query_arg(did.to_string())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(result.rows_affected() > 0)
    }

    async fn save_webauthn_challenge(
        &self,
        did: &Did,
        challenge_type: WebauthnChallengeType,
        state_json: &str,
    ) -> Result<Uuid, DbError> {
        let id = Uuid::new_v4();
        let challenge = id.as_bytes().to_vec();
        let expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);
        sqlite_query!(r#"INSERT INTO webauthn_challenges (id, did, challenge, challenge_type, state_json, expires_at)
               VALUES ($1, $2, $3, $4, $5, $6)"#,
            id,
            query_arg(did.to_string()),
            challenge,
            query_arg(challenge_type.as_str().to_owned()),
            state_json,
            expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(id)
    }

    async fn load_webauthn_challenge(
        &self,
        did: &Did,
        challenge_type: WebauthnChallengeType,
    ) -> Result<Option<String>, DbError> {
        let row = sqlite_query_scalar_unchecked!(
            r#"SELECT state_json FROM webauthn_challenges
               WHERE did = $1 AND challenge_type = $2 AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
               ORDER BY created_at DESC LIMIT 1"#,
            query_arg(did.to_string()),
            query_arg(challenge_type.as_str().to_owned())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(row)
    }

    async fn delete_webauthn_challenge(
        &self,
        did: &Did,
        challenge_type: WebauthnChallengeType,
    ) -> Result<(), DbError> {
        sqlite_query!(
            "DELETE FROM webauthn_challenges WHERE did = $1 AND challenge_type = $2",
            query_arg(did.to_string()),
            query_arg(challenge_type.as_str().to_owned())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn save_discoverable_challenge(
        &self,
        request_key: &str,
        state_json: &str,
    ) -> Result<Uuid, DbError> {
        let id = Uuid::new_v4();
        let challenge = id.as_bytes().to_vec();
        let expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);
        sqlite_query!(r#"INSERT INTO webauthn_challenges (id, did, challenge, challenge_type, state_json, expires_at)
               VALUES ($1, $2, $3, 'discoverable', $4, $5)"#,
            id,
            request_key,
            challenge,
            state_json,
            expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(id)
    }

    async fn load_discoverable_challenge(
        &self,
        request_key: &str,
    ) -> Result<Option<String>, DbError> {
        let row = sqlite_query_scalar_unchecked!(
            r#"SELECT state_json FROM webauthn_challenges
               WHERE did = $1 AND challenge_type = 'discoverable' AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
               ORDER BY created_at DESC LIMIT 1"#,
            request_key,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(row)
    }

    async fn delete_discoverable_challenge(&self, request_key: &str) -> Result<(), DbError> {
        sqlite_query!(
            "DELETE FROM webauthn_challenges WHERE did = $1 AND challenge_type = 'discoverable'",
            request_key,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn get_totp_record(&self, did: &Did) -> Result<Option<TotpRecord>, DbError> {
        let row = sqlite_query_unchecked!(
            "SELECT secret_encrypted, encryption_version, verified FROM user_totp WHERE did = $1",
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            Ok(TotpRecord {
                secret_encrypted: r.secret_encrypted,
                encryption_version: parse_i32(r.encryption_version)?,
                verified: r.verified != 0,
            })
        })
        .transpose()
    }

    async fn get_totp_record_state(&self, did: &Did) -> Result<Option<TotpRecordState>, DbError> {
        self.get_totp_record(did)
            .await
            .map(|opt| opt.map(TotpRecordState::from))
    }

    async fn upsert_totp_secret(
        &self,
        did: &Did,
        secret_encrypted: &[u8],
        encryption_version: i32,
    ) -> Result<(), DbError> {
        sqlite_query!(r#"INSERT INTO user_totp (did, secret_encrypted, encryption_version, verified, created_at)
               VALUES ($1, $2, $3, false, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
               ON CONFLICT (did) DO UPDATE SET
                   secret_encrypted = $2,
                   encryption_version = $3,
                   verified = false,
                   created_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                   last_used = NULL"#,
            query_arg(did.to_string()),
            secret_encrypted,
            encryption_version
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn set_totp_verified(&self, did: &Did) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE user_totp SET verified = true, last_used = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE did = $1",
            query_arg(did.to_string())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn update_totp_last_used(&self, did: &Did) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE user_totp SET last_used = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE did = $1",
            query_arg(did.to_string())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn delete_totp(&self, did: &Did) -> Result<(), DbError> {
        sqlite_query!(
            "DELETE FROM user_totp WHERE did = $1",
            query_arg(did.to_string())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn get_unused_backup_codes(&self, did: &Did) -> Result<Vec<StoredBackupCode>, DbError> {
        let rows = sqlite_query_unchecked!(
            "SELECT id, code_hash FROM backup_codes WHERE did = $1 AND used_at IS NULL",
            query_arg(did.to_string())
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        rows.into_iter()
            .map(|r| {
                Ok(StoredBackupCode {
                    id: parse_uuid(r.id.ok_or(DbError::NotFound)?)?,
                    code_hash: r.code_hash,
                })
            })
            .collect()
    }

    async fn mark_backup_code_used(&self, code_id: Uuid) -> Result<bool, DbError> {
        let result = sqlite_query!(
            "UPDATE backup_codes SET used_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = $1",
            code_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(result.rows_affected() > 0)
    }

    async fn count_unused_backup_codes(&self, did: &Did) -> Result<i64, DbError> {
        let row = sqlite_query_unchecked!(
            "SELECT COUNT(*) as count FROM backup_codes WHERE did = $1 AND used_at IS NULL",
            query_arg(did.to_string())
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(row.count)
    }

    async fn delete_backup_codes(&self, did: &Did) -> Result<u64, DbError> {
        let result = sqlite_query!(
            "DELETE FROM backup_codes WHERE did = $1",
            query_arg(did.to_string())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(result.rows_affected())
    }

    async fn insert_backup_codes(&self, did: &Did, code_hashes: &[String]) -> Result<(), DbError> {
        for code_hash in code_hashes {
            sqlite_query!(
                "INSERT INTO backup_codes (did, code_hash, created_at) VALUES ($1, $2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                did.to_string(),
                code_hash,
            )
            .execute(&self.pool)
            .await
            .map_err(map_sqlite_error)?;
        }

        Ok(())
    }

    async fn enable_totp_with_backup_codes(
        &self,
        did: &Did,
        code_hashes: &[String],
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlite_error)?;

        sqlite_query!(
            "UPDATE user_totp SET verified = true, last_used = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE did = $1",
            query_arg(did.to_string())
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;

        sqlite_query!(
            "DELETE FROM backup_codes WHERE did = $1",
            query_arg(did.to_string())
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;

        for code_hash in code_hashes {
            sqlite_query!(
                "INSERT INTO backup_codes (did, code_hash, created_at) VALUES ($1, $2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                did.to_string(),
                code_hash,
            )
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;
        }

        tx.commit().await.map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn delete_totp_and_backup_codes(&self, did: &Did) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlite_error)?;

        sqlite_query!(
            "DELETE FROM user_totp WHERE did = $1",
            query_arg(did.to_string())
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;

        sqlite_query!(
            "DELETE FROM backup_codes WHERE did = $1",
            query_arg(did.to_string())
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;

        tx.commit().await.map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn replace_backup_codes(&self, did: &Did, code_hashes: &[String]) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlite_error)?;

        sqlite_query!(
            "DELETE FROM backup_codes WHERE did = $1",
            query_arg(did.to_string())
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;

        for code_hash in code_hashes {
            sqlite_query!(
                "INSERT INTO backup_codes (did, code_hash, created_at) VALUES ($1, $2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                did.to_string(),
                code_hash,
            )
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;
        }

        tx.commit().await.map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn get_login_check_by_identifier(
        &self,
        identifier: &AtIdentifier,
    ) -> Result<Option<UserLoginCheck>, DbError> {
        sqlite_query_unchecked!(
            "SELECT did, password_hash FROM users WHERE handle = $1 OR did = $1",
            query_arg(identifier.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?
        .map(|r| {
            Ok(UserLoginCheck {
                did: column(r.did, col::USERS_DID)?,
                password_hash: r.password_hash.map(PasswordHash::new),
            })
        })
        .transpose()
    }

    async fn get_login_info_by_identifier(
        &self,
        identifier: &AtIdentifier,
    ) -> Result<Option<UserLoginInfo>, DbError> {
        sqlite_query_unchecked!(
            r#"
            SELECT id, did, email, password_hash, password_required, two_factor_enabled,
                   preferred_comms_channel as "preferred_comms_channel!: CommsChannel",
                   deactivated_at, takedown_ref,
                   email_verified, discord_verified, telegram_verified, signal_verified,
                   account_type as "account_type!: AccountType"
            FROM users
            WHERE handle = $1 OR did = $1
            "#,
            query_arg(identifier.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?
        .map(|row| {
            Ok(UserLoginInfo {
                id: parse_uuid(row.id.ok_or(DbError::NotFound)?)?,
                did: column(row.did, col::USERS_DID)?,
                email: row.email,
                password_hash: row.password_hash.map(PasswordHash::new),
                password_required: row.password_required != 0,
                two_factor_enabled: row.two_factor_enabled != 0,
                preferred_comms_channel: row.preferred_comms_channel,
                deactivated_at: parse_optional_timestamp(row.deactivated_at)?,
                takedown_ref: row.takedown_ref,
                channel_verification: ChannelVerificationStatus::from_db_row(
                    row.email_verified != 0,
                    row.discord_verified != 0,
                    row.telegram_verified != 0,
                    row.signal_verified != 0,
                ),
                account_type: row.account_type,
            })
        })
        .transpose()
    }

    async fn get_2fa_status_by_did(&self, did: &Did) -> Result<Option<User2faStatus>, DbError> {
        let row = sqlite_query_unchecked!(
            r#"
            SELECT id, two_factor_enabled,
                   preferred_comms_channel as "preferred_comms_channel!: CommsChannel",
                   email_verified, discord_verified, telegram_verified, signal_verified
            FROM users
            WHERE did = $1
            "#,
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        row.map(|row| {
            Ok(User2faStatus {
                id: parse_uuid(row.id.ok_or(DbError::NotFound)?)?,
                two_factor_enabled: row.two_factor_enabled != 0,
                preferred_comms_channel: row.preferred_comms_channel,
                channel_verification: ChannelVerificationStatus::from_db_row(
                    row.email_verified != 0,
                    row.discord_verified != 0,
                    row.telegram_verified != 0,
                    row.signal_verified != 0,
                ),
            })
        })
        .transpose()
    }

    async fn get_session_info_by_did(&self, did: &Did) -> Result<Option<UserSessionInfo>, DbError> {
        sqlite_query_unchecked!(
            r#"
            SELECT u.handle, u.email, u.email_verified, u.is_admin, u.deactivated_at, u.takedown_ref,
                   u.preferred_locale,
                   u.preferred_comms_channel as "preferred_comms_channel!: CommsChannel",
                   u.discord_verified, u.telegram_verified, u.signal_verified,
                   u.migrated_to_pds, u.migrated_at,
                   (SELECT verified FROM user_totp WHERE did = u.did) as totp_enabled,
                   COALESCE((SELECT CAST(value_json AS INTEGER) FROM account_preferences WHERE user_id = u.id AND name = 'email_auth_factor' ORDER BY created_at DESC LIMIT 1), 0) as "email_2fa_enabled!: i64"
            FROM users u
            WHERE u.did = $1
            "#,
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?
        .map(|row| {
            Ok(UserSessionInfo {
                handle: column(row.handle, col::USERS_HANDLE)?,
                email: row.email,
                is_admin: row.is_admin != 0,
                deactivated_at: parse_optional_timestamp(row.deactivated_at)?,
                takedown_ref: row.takedown_ref,
                preferred_locale: row.preferred_locale,
                preferred_comms_channel: row.preferred_comms_channel,
                channel_verification: ChannelVerificationStatus::from_db_row(
                    row.email_verified != 0,
                    row.discord_verified != 0,
                    row.telegram_verified != 0,
                    row.signal_verified != 0,
                ),
                migrated_to_pds: row.migrated_to_pds,
                migrated_at: parse_optional_timestamp(row.migrated_at)?,
                totp_enabled: row.totp_enabled != 0,
                email_2fa_enabled: row.email_2fa_enabled != 0
            })
        })
        .transpose()
    }

    async fn get_legacy_login_pref(
        &self,
        did: &Did,
    ) -> Result<Option<UserLegacyLoginPref>, DbError> {
        sqlite_query_unchecked!(
            r#"
            SELECT u.allow_legacy_login,
                   (EXISTS(SELECT 1 FROM user_totp t WHERE t.did = u.did AND t.verified = TRUE) OR
                    EXISTS(SELECT 1 FROM passkeys p WHERE p.did = u.did)) as "has_mfa!: i64"
            FROM users u
            WHERE u.did = $1
            "#,
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)
        .map(|opt| {
            opt.map(|row| UserLegacyLoginPref {
                allow_legacy_login: row.allow_legacy_login != 0,
                has_mfa: row.has_mfa != 0,
            })
        })
    }

    async fn update_legacy_login(&self, did: &Did, allow: bool) -> Result<bool, DbError> {
        let result = sqlite_query!(
            "UPDATE users SET allow_legacy_login = $1 WHERE did = $2 RETURNING did",
            allow,
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(result.is_some())
    }

    async fn update_locale(&self, did: &Did, locale: &str) -> Result<bool, DbError> {
        let result = sqlite_query!(
            "UPDATE users SET preferred_locale = $1 WHERE did = $2 RETURNING did",
            locale,
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(result.is_some())
    }

    async fn get_login_full_by_identifier(
        &self,
        identifier: &AtIdentifier,
    ) -> Result<Option<UserLoginFull>, DbError> {
        sqlite_query_unchecked!(
            r#"SELECT
                u.id, u.did, u.handle, u.password_hash, u.email, u.deactivated_at, u.takedown_ref,
                u.email_verified, u.discord_verified, u.telegram_verified, u.signal_verified,
                u.allow_legacy_login, u.migrated_to_pds,
                u.preferred_comms_channel as "preferred_comms_channel: CommsChannel",
                k.key_bytes, k.encryption_version,
                (SELECT verified FROM user_totp WHERE did = u.did) as totp_enabled,
                COALESCE((SELECT CAST(value_json AS INTEGER) FROM account_preferences WHERE user_id = u.id AND name = 'email_auth_factor' ORDER BY created_at DESC LIMIT 1), 0) as "email_2fa_enabled!: i64"
            FROM users u
            JOIN user_keys k ON u.id = k.user_id
            WHERE u.handle = $1 OR u.did = $1"#,
            query_arg(identifier.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?
        .map(|row| {
            Ok(UserLoginFull {
                id: parse_uuid(row.id.ok_or(DbError::NotFound)?)?,
                did: column(row.did, col::USERS_DID)?,
                handle: column(row.handle, col::USERS_HANDLE)?,
                password_hash: row.password_hash.map(PasswordHash::new),
                email: row.email,
                deactivated_at: parse_optional_timestamp(row.deactivated_at)?,
                takedown_ref: row.takedown_ref,
                channel_verification: ChannelVerificationStatus::from_db_row(
                    row.email_verified != 0,
                    row.discord_verified != 0,
                    row.telegram_verified != 0,
                    row.signal_verified != 0,
                ),
                allow_legacy_login: row.allow_legacy_login != 0,
                migrated_to_pds: row.migrated_to_pds,
                preferred_comms_channel: row.preferred_comms_channel,
                key_bytes: row.key_bytes,
                encryption_version: row.encryption_version.map(parse_i32).transpose()?,
                totp_enabled: row.totp_enabled != 0,
                email_2fa_enabled: row.email_2fa_enabled != 0
            })
        })
        .transpose()
    }

    async fn get_confirm_signup_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserConfirmSignup>, DbError> {
        sqlite_query_unchecked!(
            r#"SELECT
                u.id, u.did, u.handle, u.email,
                u.preferred_comms_channel as "channel: CommsChannel",
                u.discord_username, u.telegram_username, u.signal_username,
                k.key_bytes, k.encryption_version
            FROM users u
            JOIN user_keys k ON u.id = k.user_id
            WHERE u.did = $1"#,
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?
        .map(|row| {
            Ok(UserConfirmSignup {
                id: parse_uuid(row.id.ok_or(DbError::NotFound)?)?,
                did: column(row.did, col::USERS_DID)?,
                handle: column(row.handle, col::USERS_HANDLE)?,
                email: row.email,
                channel: row.channel,
                discord_username: row.discord_username,
                telegram_username: row.telegram_username,
                signal_username: row.signal_username,
                key_bytes: row.key_bytes,
                encryption_version: row.encryption_version.map(parse_i32).transpose()?,
            })
        })
        .transpose()
    }

    async fn get_resend_verification_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserResendVerification>, DbError> {
        sqlite_query_unchecked!(
            r#"SELECT
                id, handle, email,
                preferred_comms_channel as "channel: CommsChannel",
                discord_username, telegram_username, signal_username,
                email_verified, discord_verified, telegram_verified, signal_verified
            FROM users
            WHERE did = $1"#,
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?
        .map(|row| {
            Ok(UserResendVerification {
                id: parse_uuid(row.id.ok_or(DbError::NotFound)?)?,
                handle: column(row.handle, col::USERS_HANDLE)?,
                email: row.email,
                channel: row.channel,
                discord_username: row.discord_username,
                telegram_username: row.telegram_username,
                signal_username: row.signal_username,
                channel_verification: ChannelVerificationStatus::from_db_row(
                    row.email_verified != 0,
                    row.discord_verified != 0,
                    row.telegram_verified != 0,
                    row.signal_verified != 0,
                ),
            })
        })
        .transpose()
    }

    async fn set_channel_verified(&self, did: &Did, channel: CommsChannel) -> Result<(), DbError> {
        let column = match channel {
            CommsChannel::Email => "email_verified",
            CommsChannel::Discord => "discord_verified",
            CommsChannel::Telegram => "telegram_verified",
            CommsChannel::Signal => "signal_verified",
        };
        let query = format!("UPDATE users SET {} = TRUE WHERE did = $1", column);
        sqlite_query!(&query, query_arg(did.to_string()))
            .execute(&self.pool)
            .await
            .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn get_id_by_email_or_handle(
        &self,
        email: &str,
        handle: &Handle,
    ) -> Result<Option<Uuid>, DbError> {
        sqlite_query_scalar_unchecked!(
            "SELECT id FROM users WHERE LOWER(email) = $1 OR handle = $2",
            email,
            query_arg(handle.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)
        .and_then(|row| row.flatten().map(parse_uuid).transpose())
    }

    async fn count_accounts_by_email(&self, email: &str) -> Result<i64, DbError> {
        sqlite_query_scalar_unchecked!(
            "SELECT COUNT(*) FROM users WHERE LOWER(email) = LOWER($1) AND deactivated_at IS NULL",
            email
        )
        .fetch_one(&self.pool)
        .await
        .map(|c| c)
        .map_err(map_sqlite_error)
    }

    async fn get_handles_by_email(&self, email: &str) -> Result<Vec<Handle>, DbError> {
        let handles = sqlite_query_scalar_unchecked!(
            "SELECT handle FROM users WHERE LOWER(email) = LOWER($1) AND deactivated_at IS NULL ORDER BY created_at DESC",
            email
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(handles
            .into_iter()
            .filter_map(|h| legacy_column(h, col::USERS_HANDLE))
            .collect())
    }

    async fn set_password_reset_code(
        &self,
        user_id: Uuid,
        code: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE users SET password_reset_code = $1, password_reset_code_expires_at = $2 WHERE id = $3",
            code,
            expires_at,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn get_user_by_reset_code(
        &self,
        code: &str,
    ) -> Result<Option<UserResetCodeInfo>, DbError> {
        sqlite_query_unchecked!(
            "SELECT id, did, preferred_comms_channel as \"preferred_comms_channel: CommsChannel\", password_reset_code_expires_at FROM users WHERE password_reset_code = $1",
            code
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?
        .map(|row| {
            Ok(UserResetCodeInfo {
                id: parse_uuid(row.id.ok_or(DbError::NotFound)?)?,
                did: column(row.did, col::USERS_DID)?,
                preferred_comms_channel: row.preferred_comms_channel,
                expires_at: parse_optional_timestamp(row.password_reset_code_expires_at)?,
            })
        })
        .transpose()
    }

    async fn clear_password_reset_code(&self, user_id: Uuid) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE users SET password_reset_code = NULL, password_reset_code_expires_at = NULL WHERE id = $1",
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn get_id_and_password_hash_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserIdAndPasswordHash>, DbError> {
        let row = sqlite_query_unchecked!(
            "SELECT id, password_hash FROM users WHERE did = $1",
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        match row {
            Some(row) => match row.password_hash {
                Some(hash) => Ok(Some(UserIdAndPasswordHash {
                    id: parse_uuid(row.id.ok_or(DbError::NotFound)?)?,
                    password_hash: PasswordHash::new(hash),
                })),
                None => Ok(None),
            },
            None => Ok(None),
        }
    }

    async fn update_password_hash(
        &self,
        user_id: Uuid,
        password_hash: &PasswordHash,
    ) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE users SET password_hash = $1 WHERE id = $2",
            query_arg(password_hash.as_str().to_owned()),
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn reset_password_with_sessions(
        &self,
        user_id: Uuid,
        password_hash: &PasswordHash,
    ) -> Result<PasswordResetResult, DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlite_error)?;

        sqlite_query!(
            "UPDATE users SET password_hash = $1, password_reset_code = NULL, password_reset_code_expires_at = NULL, password_required = TRUE WHERE id = $2",
            query_arg(password_hash.as_str().to_owned()),
            user_id
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;

        let user_did =
            sqlite_query_scalar_unchecked!("SELECT did FROM users WHERE id = $1", user_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(map_sqlite_error)?;

        let session_jtis: Vec<Jti> = sqlite_query_scalar_unchecked!(
            "SELECT access_jti FROM session_tokens WHERE did = $1",
            user_did.clone()
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(map_sqlite_error)?
        .into_iter()
        .map(Jti::from)
        .collect();

        sqlite_query!(
            "DELETE FROM session_tokens WHERE did = $1",
            user_did.clone()
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;

        let did = column(user_did, col::USERS_DID)?;

        tx.commit().await.map_err(map_sqlite_error)?;

        Ok(PasswordResetResult { did, session_jtis })
    }

    async fn activate_account(&self, did: &Did) -> Result<bool, DbError> {
        let result = sqlite_query!(
            "UPDATE users SET deactivated_at = NULL, inbound_migration = FALSE WHERE did = $1",
            query_arg(did.to_string())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn deactivate_account(
        &self,
        did: &Did,
        delete_after: Option<DateTime<Utc>>,
    ) -> Result<bool, DbError> {
        let result = sqlite_query!(
            "UPDATE users SET deactivated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), delete_after = $2 WHERE did = $1",
            query_arg(did.to_string()),
            delete_after
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn has_password_by_did(&self, did: &Did) -> Result<Option<bool>, DbError> {
        sqlite_query_scalar_unchecked!(
            "SELECT password_hash IS NOT NULL as \"has_password!: i64\" FROM users WHERE did = $1",
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)
        .map(|opt| opt.map(|value| value != 0))
    }

    async fn get_password_info_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserPasswordInfo>, DbError> {
        let row = sqlite_query_unchecked!(
            "SELECT id, password_hash FROM users WHERE did = $1",
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        row.map(|row| {
            Ok(UserPasswordInfo {
                id: parse_uuid(row.id.ok_or(DbError::NotFound)?)?,
                password_hash: row.password_hash.map(PasswordHash::new),
            })
        })
        .transpose()
    }

    async fn remove_user_password(&self, user_id: Uuid) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE users SET password_hash = NULL, password_required = FALSE WHERE id = $1",
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn set_new_user_password(
        &self,
        user_id: Uuid,
        password_hash: &PasswordHash,
    ) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE users SET password_hash = $1, password_required = TRUE WHERE id = $2",
            query_arg(password_hash.as_str().to_owned()),
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn is_account_active_by_did(&self, did: &Did) -> Result<Option<bool>, DbError> {
        sqlite_query_scalar_unchecked!(
            "SELECT deactivated_at IS NULL as \"is_active!: i64\" FROM users WHERE did = $1",
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)
        .map(|opt| opt.map(|value| value != 0))
    }

    async fn get_user_for_deletion(&self, did: &Did) -> Result<Option<UserForDeletion>, DbError> {
        sqlite_query_unchecked!(
            "SELECT id, password_hash, handle FROM users WHERE did = $1",
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?
        .map(|row| {
            Ok(UserForDeletion {
                id: parse_uuid(row.id.ok_or(DbError::NotFound)?)?,
                password_hash: row.password_hash.map(PasswordHash::new),
                handle: column(row.handle, col::USERS_HANDLE)?,
            })
        })
        .transpose()
    }

    async fn get_user_key_by_did(&self, did: &Did) -> Result<Option<UserKeyInfo>, DbError> {
        let row = sqlite_query_unchecked!(
            r#"SELECT uk.key_bytes, uk.encryption_version
               FROM user_keys uk
               JOIN users u ON uk.user_id = u.id
               WHERE u.did = $1"#,
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        row.map(|row| {
            Ok(UserKeyInfo {
                key_bytes: row.key_bytes,
                encryption_version: row.encryption_version.map(parse_i32).transpose()?,
            })
        })
        .transpose()
    }

    async fn delete_account_complete(&self, user_id: Uuid, did: &Did) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlite_error)?;
        sqlite_query!(
            "DELETE FROM session_tokens WHERE did = $1",
            query_arg(did.to_string())
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;
        sqlite_query!("DELETE FROM records WHERE repo_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;
        sqlite_query!("DELETE FROM repos WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;
        sqlite_query!("DELETE FROM blobs WHERE created_by_user = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;
        sqlite_query!("DELETE FROM user_keys WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;
        sqlite_query!("DELETE FROM app_passwords WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;
        sqlite_query!(
            "DELETE FROM account_deletion_requests WHERE did = $1",
            query_arg(did.to_string())
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;
        sqlite_query!("DELETE FROM users WHERE id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;
        tx.commit().await.map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn set_user_takedown(
        &self,
        did: &Did,
        takedown_ref: Option<&str>,
    ) -> Result<bool, DbError> {
        let result = sqlite_query!(
            "UPDATE users SET takedown_ref = $1 WHERE did = $2",
            takedown_ref,
            query_arg(did.to_string())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn admin_delete_account_complete(&self, user_id: Uuid, did: &Did) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlite_error)?;
        sqlite_query!(
            "DELETE FROM session_tokens WHERE did = $1",
            query_arg(did.to_string())
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;
        sqlite_query!(
            "DELETE FROM used_refresh_tokens WHERE session_id IN (SELECT id FROM session_tokens WHERE did = $1)",
            query_arg(did.to_string())
        )
        .execute(&mut *tx)
        .await
        .ok();
        sqlite_query!("DELETE FROM records WHERE repo_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;
        sqlite_query!("DELETE FROM repos WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;
        sqlite_query!("DELETE FROM blobs WHERE created_by_user = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;
        sqlite_query!("DELETE FROM app_passwords WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;
        sqlite_query!(
            "DELETE FROM invite_code_uses WHERE used_by_user = $1",
            user_id
        )
        .execute(&mut *tx)
        .await
        .ok();
        sqlite_query!(
            "DELETE FROM invite_codes WHERE created_by_user = $1",
            user_id
        )
        .execute(&mut *tx)
        .await
        .ok();
        sqlite_query!("DELETE FROM user_keys WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;
        sqlite_query!("DELETE FROM users WHERE id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;
        tx.commit().await.map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn get_user_for_did_doc(&self, did: &Did) -> Result<Option<UserForDidDoc>, DbError> {
        let row = sqlite_query_unchecked!(
            "SELECT id, handle, deactivated_at FROM users WHERE did = $1",
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            Ok(UserForDidDoc {
                id: parse_uuid(r.id.ok_or(DbError::NotFound)?)?,
                handle: column(r.handle, col::USERS_HANDLE)?,
                deactivated_at: parse_optional_timestamp(r.deactivated_at)?,
            })
        })
        .transpose()
    }

    async fn get_user_for_did_doc_build(
        &self,
        did: &Did,
    ) -> Result<Option<UserForDidDocBuild>, DbError> {
        let row = sqlite_query_unchecked!(
            "SELECT id, handle, migrated_to_pds FROM users WHERE did = $1",
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            Ok(UserForDidDocBuild {
                id: parse_uuid(r.id.ok_or(DbError::NotFound)?)?,
                handle: column(r.handle, col::USERS_HANDLE)?,
                migrated_to_pds: r.migrated_to_pds,
            })
        })
        .transpose()
    }

    async fn upsert_did_web_overrides(
        &self,
        user_id: Uuid,
        verification_methods: Option<serde_json::Value>,
        also_known_as: Option<Vec<String>>,
    ) -> Result<(), DbError> {
        let now = chrono::Utc::now();
        sqlite_query!(r#"
            INSERT INTO did_web_overrides (user_id, verification_methods, also_known_as, updated_at)
            VALUES ($1, COALESCE($2, '[]'), COALESCE($3, '{}'), $4)
            ON CONFLICT (user_id) DO UPDATE SET
                verification_methods = CASE WHEN $2 IS NOT NULL THEN $2 ELSE did_web_overrides.verification_methods END,
                also_known_as = CASE WHEN $3 IS NOT NULL THEN $3 ELSE did_web_overrides.also_known_as END,
                updated_at = $4
            "#,
            user_id,
            verification_methods.map(|value| value.to_string()),
            also_known_as.map(|value| serde_json::to_string(&value)).transpose()
                .map_err(|error| DbError::Other(format!("failed to serialize DID Web aliases: {error}")))?,
            now
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn update_migrated_to_pds(&self, did: &Did, endpoint: &str) -> Result<(), DbError> {
        let now = chrono::Utc::now();
        sqlite_query!(
            "UPDATE users SET migrated_to_pds = $1, migrated_at = $2 WHERE did = $3",
            endpoint,
            now,
            query_arg(did.to_string())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn get_user_for_passkey_setup(
        &self,
        did: &Did,
    ) -> Result<Option<UserForPasskeySetup>, DbError> {
        let row = sqlite_query_unchecked!(
            r#"SELECT id, handle, recovery_token, recovery_token_expires_at, password_required
               FROM users WHERE did = $1"#,
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            Ok(UserForPasskeySetup {
                id: parse_uuid(r.id.ok_or(DbError::NotFound)?)?,
                handle: column(r.handle, col::USERS_HANDLE)?,
                recovery_token: r.recovery_token,
                recovery_token_expires_at: parse_optional_timestamp(r.recovery_token_expires_at)?,
                password_required: r.password_required != 0,
            })
        })
        .transpose()
    }

    async fn get_user_for_passkey_recovery(
        &self,
        identifier: &str,
        normalized_handle: &str,
    ) -> Result<Option<UserForPasskeyRecovery>, DbError> {
        let row = sqlite_query_unchecked!(
            "SELECT id, did, handle, password_required FROM users WHERE LOWER(email) = $1 OR handle = $2",
            identifier,
            normalized_handle
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            Ok(UserForPasskeyRecovery {
                id: parse_uuid(r.id.ok_or(DbError::NotFound)?)?,
                did: column(r.did, col::USERS_DID)?,
                handle: column(r.handle, col::USERS_HANDLE)?,
                password_required: r.password_required != 0,
            })
        })
        .transpose()
    }

    async fn set_recovery_token(
        &self,
        did: &Did,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE users SET recovery_token = $1, recovery_token_expires_at = $2 WHERE did = $3",
            token_hash,
            expires_at,
            query_arg(did.to_string())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn get_user_for_recovery(&self, did: &Did) -> Result<Option<UserForRecovery>, DbError> {
        let row = sqlite_query_unchecked!(
            "SELECT id, did, preferred_comms_channel as \"preferred_comms_channel: CommsChannel\", recovery_token, recovery_token_expires_at FROM users WHERE did = $1",
            query_arg(did.to_string())
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            Ok(UserForRecovery {
                id: parse_uuid(r.id.ok_or(DbError::NotFound)?)?,
                did: column(r.did, col::USERS_DID)?,
                preferred_comms_channel: r.preferred_comms_channel,
                recovery_token: r.recovery_token,
                recovery_token_expires_at: parse_optional_timestamp(r.recovery_token_expires_at)?,
            })
        })
        .transpose()
    }

    async fn get_accounts_scheduled_for_deletion(
        &self,
        limit: i64,
    ) -> Result<Vec<tranquil_db_traits::ScheduledDeletionAccount>, DbError> {
        let rows = sqlite_query_unchecked!(
            r#"
            SELECT id, did, handle
            FROM users
            WHERE delete_after IS NOT NULL
              AND delete_after < strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
              AND deactivated_at IS NOT NULL
            LIMIT $1
            "#,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        rows.into_iter()
            .map(|r| {
                Ok(tranquil_db_traits::ScheduledDeletionAccount {
                    id: parse_uuid(r.id.ok_or(DbError::NotFound)?)?,
                    did: legacy_column(r.did, col::USERS_DID).ok_or(DbError::NotFound)?,
                    handle: legacy_column(r.handle, col::USERS_HANDLE).ok_or(DbError::NotFound)?,
                })
            })
            .collect()
    }

    async fn delete_account_with_firehose(&self, user_id: Uuid, did: &Did) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlite_error)?;

        sqlite_query!("DELETE FROM blobs WHERE created_by_user = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;

        sqlite_query!("DELETE FROM record_blobs WHERE repo_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;

        sqlite_query!("DELETE FROM records WHERE repo_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;

        sqlite_query!("DELETE FROM repos WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;

        sqlite_query!("DELETE FROM user_blocks WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;

        sqlite_query!("DELETE FROM user_keys WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;

        sqlite_query!(
            "DELETE FROM session_tokens WHERE did = $1",
            query_arg(did.to_string())
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;

        sqlite_query!("DELETE FROM app_passwords WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;

        sqlite_query!(
            "DELETE FROM passkeys WHERE did = $1",
            query_arg(did.to_string())
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;

        sqlite_query!(
            "DELETE FROM user_totp WHERE did = $1",
            query_arg(did.to_string())
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;

        sqlite_query!(
            "DELETE FROM backup_codes WHERE did = $1",
            query_arg(did.to_string())
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;

        sqlite_query!(
            "DELETE FROM webauthn_challenges WHERE did = $1",
            query_arg(did.to_string())
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;

        sqlite_query!(
            "DELETE FROM account_deletion_requests WHERE did = $1",
            query_arg(did.to_string())
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;

        sqlite_query!("DELETE FROM users WHERE id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlite_error)?;

        let event_id: i64 = sqlite_query_scalar_unchecked!(
            r#"
            INSERT INTO repo_seq (did, event_type, active, status)
            VALUES ($1, 'account', false, 'deleted')
            RETURNING id
            "#,
            query_arg(did.to_string())
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;

        sqlite_query!(
            "DELETE FROM repo_seq WHERE did = $1 AND id <> $2",
            query_arg(did.to_string()),
            event_id
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;

        tx.commit().await.map_err(map_sqlite_error)?;

        // SQLite uses the in-process repository event notifier.

        Ok(())
    }

    async fn create_password_account(
        &self,
        input: &tranquil_db_traits::CreatePasswordAccountInput,
    ) -> Result<
        tranquil_db_traits::CreatePasswordAccountResult,
        tranquil_db_traits::CreateAccountError,
    > {
        tracing::info!(did = %input.did, handle = %input.handle, "create_password_account: starting transaction");
        let mut tx = self.pool.begin().await.map_err(|e: sqlx::Error| {
            tracing::error!(
                "create_password_account: failed to begin transaction: {}",
                e
            );
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        let is_first_user: bool =
            sqlite_query_scalar_unchecked!("SELECT COUNT(*) as count FROM users")
                .fetch_one(&mut *tx)
                .await
                .map(|c| c == 0)
                .unwrap_or(false);

        let user_insert: Result<(uuid::Uuid,), _> = sqlx::query_as::<_, (uuid::Uuid,)>(
            r#"INSERT INTO users (
                handle, email, did, password_hash,
                preferred_comms_channel,
                discord_username, telegram_username, signal_username,
                is_admin, deactivated_at, inbound_migration, email_verified
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, FALSE) RETURNING id"#,
        )
        .bind(query_str(input.handle.as_str()))
        .bind(&input.email)
        .bind(query_str(input.did.as_str()))
        .bind(&input.password_hash)
        .bind(input.preferred_comms_channel)
        .bind(&input.discord_username)
        .bind(&input.telegram_username)
        .bind(&input.signal_username)
        .bind(is_first_user)
        .bind(input.deactivated_at)
        .bind(input.inbound_migration)
        .fetch_one(&mut *tx)
        .await;

        let user_id = match user_insert {
            Ok((id,)) => {
                tracing::info!(did = %input.did, user_id = %id, "create_password_account: user row inserted");
                id
            }
            Err(e) => {
                tracing::error!(did = %input.did, error = %e, "create_password_account: user insert failed");
                if let Some(db_err) = e.as_database_error()
                    && (db_err.code().as_deref() == Some("23505")
                        || db_err.is_unique_violation()
                        || db_err.message().contains("UNIQUE constraint failed"))
                {
                    let constraint = db_err.constraint().unwrap_or(db_err.message());
                    if constraint.contains("handle") {
                        return Err(tranquil_db_traits::CreateAccountError::HandleTaken);
                    } else if constraint.contains("email") {
                        return Err(tranquil_db_traits::CreateAccountError::EmailTaken);
                    } else if constraint.contains("did") {
                        return Err(tranquil_db_traits::CreateAccountError::DidExists);
                    }
                }
                return Err(tranquil_db_traits::CreateAccountError::Database(
                    e.to_string(),
                ));
            }
        };

        sqlite_query!(
            "INSERT INTO user_keys (user_id, key_bytes, encryption_version, encrypted_at) VALUES ($1, $2, $3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            user_id,
            &input.encrypted_key_bytes[..],
            input.encryption_version
        )
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| tranquil_db_traits::CreateAccountError::Database(e.to_string()))?;

        if let Some(key_id) = input.reserved_key_id {
            sqlite_query!(
                "UPDATE reserved_signing_keys SET used_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = $1",
                key_id
            )
            .execute(&mut *tx)
            .await
            .map_err(|e: sqlx::Error| {
                tranquil_db_traits::CreateAccountError::Database(e.to_string())
            })?;
        }

        sqlite_query!(
            "INSERT INTO repos (user_id, repo_root_cid, repo_rev) VALUES ($1, $2, $3)",
            user_id,
            input.commit_cid.as_str(),
            input.repo_rev.as_str()
        )
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        for block_cid in &input.genesis_block_cids {
            sqlite_query!(
                "INSERT INTO user_blocks (user_id, block_cid, repo_rev) VALUES ($1, $2, $3) ON CONFLICT (user_id, block_cid) DO NOTHING",
                user_id,
                block_cid,
                &input.repo_rev,
            )
            .execute(&mut *tx)
            .await
            .map_err(|e: sqlx::Error| {
                tranquil_db_traits::CreateAccountError::Database(e.to_string())
            })?;
        }

        if let Some(code) = &input.invite_code {
            consume_invite_code(&mut tx, code, user_id).await?;
        }

        if let Some(birthdate_pref) = &input.birthdate_pref {
            let _ = sqlite_query!(
                "INSERT INTO account_preferences (user_id, name, value_json) VALUES ($1, $2, $3)",
                user_id,
                "app.bsky.actor.defs#personalDetailsPref",
                birthdate_pref
            )
            .execute(&mut *tx)
            .await;
        }

        tracing::info!(did = %input.did, user_id = %user_id, "create_password_account: committing transaction");
        tx.commit().await.map_err(|e: sqlx::Error| {
            tracing::error!(did = %input.did, user_id = %user_id, error = %e, "create_password_account: commit failed");
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;
        tracing::info!(did = %input.did, user_id = %user_id, "create_password_account: transaction committed successfully");

        Ok(tranquil_db_traits::CreatePasswordAccountResult {
            user_id,
            is_admin: is_first_user,
        })
    }

    async fn create_delegated_account(
        &self,
        input: &tranquil_db_traits::CreateDelegatedAccountInput,
    ) -> Result<uuid::Uuid, tranquil_db_traits::CreateAccountError> {
        let mut tx = self.pool.begin().await.map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        let user_insert: Result<(uuid::Uuid,), _> = sqlx::query_as::<_, (uuid::Uuid,)>(
            r#"INSERT INTO users (
                handle, email, did, password_hash, password_required,
                account_type, preferred_comms_channel
            ) VALUES ($1, $2, $3, NULL, FALSE, 'delegated', 'email') RETURNING id"#,
        )
        .bind(query_str(input.handle.as_str()))
        .bind(&input.email)
        .bind(query_str(input.did.as_str()))
        .fetch_one(&mut *tx)
        .await;

        let user_id = match user_insert {
            Ok((id,)) => id,
            Err(e) => {
                if let Some(db_err) = e.as_database_error()
                    && (db_err.code().as_deref() == Some("23505")
                        || db_err.is_unique_violation()
                        || db_err.message().contains("UNIQUE constraint failed"))
                {
                    let constraint = db_err.constraint().unwrap_or(db_err.message());
                    if constraint.contains("handle") {
                        return Err(tranquil_db_traits::CreateAccountError::HandleTaken);
                    } else if constraint.contains("email") {
                        return Err(tranquil_db_traits::CreateAccountError::EmailTaken);
                    }
                }
                return Err(tranquil_db_traits::CreateAccountError::Database(
                    e.to_string(),
                ));
            }
        };

        sqlite_query!(
            "INSERT INTO user_keys (user_id, key_bytes, encryption_version, encrypted_at) VALUES ($1, $2, $3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            user_id,
            &input.encrypted_key_bytes[..],
            input.encryption_version
        )
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| tranquil_db_traits::CreateAccountError::Database(e.to_string()))?;

        sqlite_query!(r#"INSERT INTO account_delegations (delegated_did, controller_did, granted_scopes, granted_by)
               VALUES ($1, $2, $3, $4)"#,
            query_arg(input.did.to_string()),
            query_arg(input.controller_did.to_string()),
            &input.controller_scopes,
            query_arg(input.controller_did.to_string())
        )
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| tranquil_db_traits::CreateAccountError::Database(e.to_string()))?;

        sqlite_query!(
            "INSERT INTO repos (user_id, repo_root_cid, repo_rev) VALUES ($1, $2, $3)",
            user_id,
            input.commit_cid.as_str(),
            input.repo_rev.as_str()
        )
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        for block_cid in &input.genesis_block_cids {
            sqlite_query!(
                "INSERT INTO user_blocks (user_id, block_cid, repo_rev) VALUES ($1, $2, $3) ON CONFLICT (user_id, block_cid) DO NOTHING",
                user_id,
                block_cid,
                &input.repo_rev,
            )
            .execute(&mut *tx)
            .await
            .map_err(|e: sqlx::Error| {
                tranquil_db_traits::CreateAccountError::Database(e.to_string())
            })?;
        }

        tx.commit().await.map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        Ok(user_id)
    }

    async fn create_passkey_account(
        &self,
        input: &tranquil_db_traits::CreatePasskeyAccountInput,
    ) -> Result<
        tranquil_db_traits::CreatePasswordAccountResult,
        tranquil_db_traits::CreateAccountError,
    > {
        let mut tx = self.pool.begin().await.map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        let is_first_user: bool =
            sqlite_query_scalar_unchecked!("SELECT COUNT(*) as count FROM users")
                .fetch_one(&mut *tx)
                .await
                .map(|c| c == 0)
                .unwrap_or(false);

        let user_insert: Result<(uuid::Uuid,), _> = sqlx::query_as::<_, (uuid::Uuid,)>(
            r#"INSERT INTO users (
                handle, email, did, password_hash, password_required,
                preferred_comms_channel,
                discord_username, telegram_username, signal_username,
                recovery_token, recovery_token_expires_at,
                is_admin, deactivated_at
            ) VALUES ($1, $2, $3, NULL, FALSE, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id"#,
        )
        .bind(query_str(input.handle.as_str()))
        .bind(&input.email)
        .bind(query_str(input.did.as_str()))
        .bind(input.preferred_comms_channel)
        .bind(&input.discord_username)
        .bind(&input.telegram_username)
        .bind(&input.signal_username)
        .bind(&input.setup_token_hash)
        .bind(input.setup_expires_at)
        .bind(is_first_user)
        .bind(input.deactivated_at)
        .fetch_one(&mut *tx)
        .await;

        let user_id = match user_insert {
            Ok((id,)) => id,
            Err(e) => {
                if let Some(db_err) = e.as_database_error()
                    && (db_err.code().as_deref() == Some("23505")
                        || db_err.is_unique_violation()
                        || db_err.message().contains("UNIQUE constraint failed"))
                {
                    let constraint = db_err.constraint().unwrap_or(db_err.message());
                    if constraint.contains("handle") {
                        return Err(tranquil_db_traits::CreateAccountError::HandleTaken);
                    } else if constraint.contains("email") {
                        return Err(tranquil_db_traits::CreateAccountError::EmailTaken);
                    }
                }
                return Err(tranquil_db_traits::CreateAccountError::Database(
                    e.to_string(),
                ));
            }
        };

        sqlite_query!(
            "INSERT INTO user_keys (user_id, key_bytes, encryption_version, encrypted_at) VALUES ($1, $2, $3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            user_id,
            &input.encrypted_key_bytes[..],
            input.encryption_version
        )
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| tranquil_db_traits::CreateAccountError::Database(e.to_string()))?;

        if let Some(key_id) = input.reserved_key_id {
            sqlite_query!(
                "UPDATE reserved_signing_keys SET used_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = $1",
                key_id
            )
            .execute(&mut *tx)
            .await
            .map_err(|e: sqlx::Error| {
                tranquil_db_traits::CreateAccountError::Database(e.to_string())
            })?;
        }

        sqlite_query!(
            "INSERT INTO repos (user_id, repo_root_cid, repo_rev) VALUES ($1, $2, $3)",
            user_id,
            input.commit_cid.as_str(),
            input.repo_rev.as_str()
        )
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        for block_cid in &input.genesis_block_cids {
            sqlite_query!(
                "INSERT INTO user_blocks (user_id, block_cid, repo_rev) VALUES ($1, $2, $3) ON CONFLICT (user_id, block_cid) DO NOTHING",
                user_id,
                block_cid,
                &input.repo_rev,
            )
            .execute(&mut *tx)
            .await
            .map_err(|e: sqlx::Error| {
                tranquil_db_traits::CreateAccountError::Database(e.to_string())
            })?;
        }

        if let Some(code) = &input.invite_code {
            consume_invite_code(&mut tx, code, user_id).await?;
        }

        if let Some(birthdate_pref) = &input.birthdate_pref {
            let _ = sqlite_query!(
                "INSERT INTO account_preferences (user_id, name, value_json) VALUES ($1, $2, $3)",
                user_id,
                "app.bsky.actor.defs#personalDetailsPref",
                birthdate_pref
            )
            .execute(&mut *tx)
            .await;
        }

        tx.commit().await.map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        Ok(tranquil_db_traits::CreatePasswordAccountResult {
            user_id,
            is_admin: is_first_user,
        })
    }

    async fn create_sso_account(
        &self,
        input: &tranquil_db_traits::CreateSsoAccountInput,
    ) -> Result<
        tranquil_db_traits::CreatePasswordAccountResult,
        tranquil_db_traits::CreateAccountError,
    > {
        let mut tx = self.pool.begin().await.map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        let token_consumed: Option<(String,)> = sqlx::query_as::<_, (String,)>(
            r#"
            DELETE FROM sso_pending_registration
            WHERE token = $1 AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            RETURNING token
            "#,
        )
        .bind(&input.pending_registration_token)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        if token_consumed.is_none() {
            return Err(tranquil_db_traits::CreateAccountError::InvalidToken);
        }

        let is_first_user: bool =
            sqlite_query_scalar_unchecked!("SELECT COUNT(*) as count FROM users")
                .fetch_one(&mut *tx)
                .await
                .map(|c| c == 0)
                .unwrap_or(false);

        let user_insert: Result<(uuid::Uuid,), _> = sqlx::query_as::<_, (uuid::Uuid,)>(
            r#"INSERT INTO users (
                handle, email, did, password_hash, password_required,
                preferred_comms_channel, discord_username, telegram_username, signal_username,
                is_admin
            ) VALUES ($1, $2, $3, NULL, FALSE, $4, $5, $6, $7, $8) RETURNING id"#,
        )
        .bind(query_str(input.handle.as_str()))
        .bind(&input.email)
        .bind(query_str(input.did.as_str()))
        .bind(input.preferred_comms_channel)
        .bind(&input.discord_username)
        .bind(&input.telegram_username)
        .bind(&input.signal_username)
        .bind(is_first_user)
        .fetch_one(&mut *tx)
        .await;

        let user_id = match user_insert {
            Ok((id,)) => id,
            Err(e) => {
                if let Some(db_err) = e.as_database_error()
                    && (db_err.code().as_deref() == Some("23505")
                        || db_err.is_unique_violation()
                        || db_err.message().contains("UNIQUE constraint failed"))
                {
                    let constraint = db_err.constraint().unwrap_or(db_err.message());
                    if constraint.contains("handle") {
                        return Err(tranquil_db_traits::CreateAccountError::HandleTaken);
                    } else if constraint.contains("email") {
                        return Err(tranquil_db_traits::CreateAccountError::EmailTaken);
                    }
                }
                return Err(tranquil_db_traits::CreateAccountError::Database(
                    e.to_string(),
                ));
            }
        };

        sqlite_query!(
            "INSERT INTO user_keys (user_id, key_bytes, encryption_version, encrypted_at) VALUES ($1, $2, $3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            user_id,
            &input.encrypted_key_bytes[..],
            input.encryption_version
        )
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| tranquil_db_traits::CreateAccountError::Database(e.to_string()))?;

        sqlite_query!(
            "INSERT INTO repos (user_id, repo_root_cid, repo_rev) VALUES ($1, $2, $3)",
            user_id,
            input.commit_cid.as_str(),
            input.repo_rev.as_str()
        )
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        for block_cid in &input.genesis_block_cids {
            sqlite_query!(
                "INSERT INTO user_blocks (user_id, block_cid, repo_rev) VALUES ($1, $2, $3) ON CONFLICT (user_id, block_cid) DO NOTHING",
                user_id,
                block_cid,
                &input.repo_rev,
            )
            .execute(&mut *tx)
            .await
            .map_err(|e: sqlx::Error| {
                tranquil_db_traits::CreateAccountError::Database(e.to_string())
            })?;
        }

        if let Some(code) = &input.invite_code {
            consume_invite_code(&mut tx, code, user_id).await?;
        }

        if let Some(birthdate_pref) = &input.birthdate_pref {
            let _ = sqlite_query!(
                "INSERT INTO account_preferences (user_id, name, value_json) VALUES ($1, $2, $3)",
                user_id,
                "app.bsky.actor.defs#personalDetailsPref",
                birthdate_pref
            )
            .execute(&mut *tx)
            .await;
        }

        sqlite_query!(r#"
            INSERT INTO external_identities (did, provider, provider_user_id, provider_username, provider_email, provider_email_verified)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            query_str(input.did.as_str()),
            input.sso_provider as SsoProviderType,
            &input.sso_provider_user_id,
            input.sso_provider_username.as_deref(),
            input.sso_provider_email.as_deref(),
            input.sso_provider_email_verified,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        tx.commit().await.map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        Ok(tranquil_db_traits::CreatePasswordAccountResult {
            user_id,
            is_admin: is_first_user,
        })
    }

    async fn reactivate_migration_account(
        &self,
        input: &tranquil_db_traits::MigrationReactivationInput,
    ) -> Result<
        tranquil_db_traits::ReactivatedAccountInfo,
        tranquil_db_traits::MigrationReactivationError,
    > {
        let mut tx =
            self.pool.begin().await.map_err(|e| {
                tranquil_db_traits::MigrationReactivationError::Database(e.to_string())
            })?;

        let existing: Option<(Vec<u8>, String, Option<String>)> =
            sqlx::query_as::<_, (Vec<u8>, String, Option<String>)>(
                "SELECT id, handle, deactivated_at FROM users WHERE did = $1",
            )
            .bind(input.did.as_str())
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| tranquil_db_traits::MigrationReactivationError::Database(e.to_string()))?;

        let (account_id, old_handle, deactivated_at) =
            existing.ok_or(tranquil_db_traits::MigrationReactivationError::NotFound)?;
        let account_id = Uuid::from_slice(&account_id)
            .map_err(|e| tranquil_db_traits::MigrationReactivationError::Database(e.to_string()))?;
        let deactivated_at = parse_optional_timestamp(deactivated_at)
            .map_err(|e| tranquil_db_traits::MigrationReactivationError::Database(e.to_string()))?;

        if deactivated_at.is_none() {
            return Err(tranquil_db_traits::MigrationReactivationError::NotDeactivated);
        }

        let update_result: Result<_, sqlx::Error> = if let Some(ref new_email) = input.new_email {
            sqlite_query!(
                "UPDATE users SET handle = $1, email = $2, email_verified = false WHERE id = $3",
                &input.new_handle,
                new_email,
                account_id,
            )
            .execute(&mut *tx)
            .await
        } else {
            sqlite_query!(
                "UPDATE users SET handle = $1 WHERE id = $2",
                &input.new_handle,
                account_id,
            )
            .execute(&mut *tx)
            .await
        };

        if let Err(e) = update_result {
            if let Some(db_err) = e.as_database_error()
                && db_err
                    .constraint()
                    .map(|c| c.contains("handle"))
                    .unwrap_or(false)
            {
                return Err(tranquil_db_traits::MigrationReactivationError::HandleTaken);
            }
            return Err(tranquil_db_traits::MigrationReactivationError::Database(
                e.to_string(),
            ));
        }

        let old_handle = legacy_column(old_handle, col::USERS_HANDLE);

        tx.commit()
            .await
            .map_err(|e| tranquil_db_traits::MigrationReactivationError::Database(e.to_string()))?;

        Ok(tranquil_db_traits::ReactivatedAccountInfo {
            user_id: account_id,
            old_handle,
        })
    }

    async fn check_handle_available_for_new_account(
        &self,
        handle: &Handle,
    ) -> Result<bool, DbError> {
        let exists: Option<(i32,)> = sqlx::query_as::<_, (i32,)>(
            r#"
            SELECT 1 FROM users WHERE handle = $1 AND deactivated_at IS NULL
            UNION ALL
            SELECT 1 FROM handle_reservations WHERE handle = $1 AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            LIMIT 1
            "#,
        )
        .bind(query_arg(handle.to_string()))
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(exists.is_none())
    }

    async fn reserve_handle(&self, handle: &Handle, reserved_by: &str) -> Result<bool, DbError> {
        sqlite_query!("DELETE FROM handle_reservations WHERE expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')")
            .execute(&self.pool)
            .await
            .map_err(map_sqlite_error)?;

        let result = sqlite_query!(r#"
            INSERT INTO handle_reservations (handle, reserved_by)
            SELECT $1, $2
            WHERE NOT EXISTS (
                SELECT 1 FROM users WHERE handle = $1 AND deactivated_at IS NULL
            )
            AND NOT EXISTS (
                SELECT 1 FROM handle_reservations WHERE handle = $1 AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            )
            "#,
            query_arg(handle.to_string()),
            reserved_by,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(result.rows_affected() > 0)
    }

    async fn release_handle_reservation(&self, handle: &Handle) -> Result<(), DbError> {
        sqlite_query!(
            "DELETE FROM handle_reservations WHERE handle = $1",
            query_arg(handle.to_string())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn cleanup_expired_handle_reservations(&self) -> Result<u64, DbError> {
        let result = sqlite_query!("DELETE FROM handle_reservations WHERE expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')")
            .execute(&self.pool)
            .await
            .map_err(map_sqlite_error)?;

        Ok(result.rows_affected())
    }

    async fn complete_passkey_setup(
        &self,
        input: &tranquil_db_traits::CompletePasskeySetupInput,
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlite_error)?;

        sqlite_query!(
            "INSERT INTO app_passwords (user_id, name, password_hash, privileged) VALUES ($1, $2, $3, FALSE)",
            input.user_id,
            &input.app_password_name,
            &input.app_password_hash
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;

        sqlite_query!(
            "UPDATE users SET recovery_token = NULL, recovery_token_expires_at = NULL WHERE did = $1",
            query_str(input.did.as_str())
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;

        tx.commit().await.map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn recover_passkey_account(
        &self,
        input: &tranquil_db_traits::RecoverPasskeyAccountInput,
    ) -> Result<tranquil_db_traits::RecoverPasskeyAccountResult, DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlite_error)?;

        sqlite_query!(
            "UPDATE users SET password_hash = $1, password_required = TRUE, recovery_token = NULL, recovery_token_expires_at = NULL WHERE did = $2",
            query_str(input.password_hash.as_str()),
            query_str(input.did.as_str())
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;

        let deleted = sqlite_query!(
            "DELETE FROM passkeys WHERE did = $1",
            query_str(input.did.as_str())
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlite_error)?;

        tx.commit().await.map_err(map_sqlite_error)?;

        Ok(tranquil_db_traits::RecoverPasskeyAccountResult {
            passkeys_deleted: deleted.rows_affected(),
        })
    }

    async fn set_unverified_telegram(
        &self,
        user_id: Uuid,
        telegram_username: &str,
    ) -> Result<(), DbError> {
        sqlite_query!(r#"UPDATE users SET
                telegram_username = $1,
                telegram_verified = CASE WHEN LOWER(telegram_username) = LOWER($1) THEN telegram_verified ELSE FALSE END,
                telegram_chat_id = CASE WHEN LOWER(telegram_username) = LOWER($1) THEN telegram_chat_id ELSE NULL END,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE id = $2"#,
            telegram_username,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn set_unverified_signal(
        &self,
        user_id: Uuid,
        signal_username: &str,
    ) -> Result<(), DbError> {
        sqlite_query!(r#"UPDATE users SET
                signal_username = $1,
                signal_verified = CASE WHEN LOWER(signal_username) = LOWER($1) THEN signal_verified ELSE FALSE END,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE id = $2"#,
            signal_username,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn set_unverified_discord(
        &self,
        user_id: Uuid,
        discord_username: &str,
    ) -> Result<(), DbError> {
        sqlite_query!(r#"UPDATE users SET
                discord_username = $1,
                discord_verified = CASE WHEN LOWER(discord_username) = LOWER($1) THEN discord_verified ELSE FALSE END,
                discord_id = CASE WHEN LOWER(discord_username) = LOWER($1) THEN discord_id ELSE NULL END,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE id = $2"#,
            discord_username,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(())
    }

    async fn store_discord_user_id(
        &self,
        discord_username: &str,
        discord_id: &str,
        handle: Option<&Handle>,
    ) -> Result<Option<Uuid>, DbError> {
        let result = match handle {
            Some(h) => sqlite_query_scalar_unchecked!(
                "UPDATE users SET discord_id = $2, discord_verified = TRUE, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE LOWER(discord_username) = LOWER($1) AND discord_username IS NOT NULL AND handle = $3 RETURNING id",
                discord_username,
                discord_id,
                h.as_str()
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlite_error)?,
            None => {
                let mut tx = self.pool.begin().await.map_err(map_sqlite_error)?;

                let matching: Vec<Uuid> = match sqlite_query_scalar_unchecked!(
                    "SELECT id FROM users WHERE LOWER(discord_username) = LOWER($1) AND discord_username IS NOT NULL AND deactivated_at IS NULL",
                    discord_username
                )
                .fetch_all(&mut *tx)
                .await
                {
                    Ok(ids) => ids
                        .into_iter()
                        .flatten()
                        .map(parse_uuid)
                        .collect::<Result<Vec<_>, _>>()?,
                    Err(sqlx::Error::Database(ref db_err))
                        if db_err.code().as_deref() == Some("55P03") =>
                    {
                        return Err(DbError::LockContention);
                    }
                    Err(e) => return Err(map_sqlite_error(e)),
                };

                let result = match matching.len() {
                    0 => None,
                    1 => {
                        sqlite_query_scalar_unchecked!(
                            "UPDATE users SET discord_id = $2, discord_verified = TRUE, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = $1 RETURNING id",
                            matching[0],
                            discord_id
                        )
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(map_sqlite_error)?
                    }
                    _ => {
                        tx.rollback().await.ok();
                        return Err(DbError::Ambiguous(
                            "Multiple accounts use this Discord username. Type: /start your-handle.example.com".to_string(),
                        ));
                    }
                };

                tx.commit().await.map_err(map_sqlite_error)?;
                result
            }
        };
        Ok(result.flatten().map(parse_uuid).transpose()?)
    }

    async fn store_telegram_chat_id(
        &self,
        telegram_username: &str,
        chat_id: i64,
        handle: Option<&Handle>,
    ) -> Result<Option<Uuid>, DbError> {
        let result = match handle {
            Some(h) => sqlite_query_scalar_unchecked!(
                "UPDATE users SET telegram_chat_id = $2, telegram_verified = TRUE, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE LOWER(telegram_username) = LOWER($1) AND telegram_username IS NOT NULL AND handle = $3 RETURNING id",
                telegram_username,
                chat_id,
                h.as_str()
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlite_error)?,
            None => sqlite_query_scalar_unchecked!(
                r#"UPDATE users SET telegram_chat_id = $2, telegram_verified = TRUE, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                WHERE id = (
                    SELECT id FROM users
                    WHERE LOWER(telegram_username) = LOWER($1) AND telegram_username IS NOT NULL AND deactivated_at IS NULL
                    LIMIT 1
                ) RETURNING id"#,
                telegram_username,
                chat_id
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlite_error)?,
        };
        Ok(result.flatten().map(parse_uuid).transpose()?)
    }

    async fn get_telegram_chat_id(&self, user_id: Uuid) -> Result<Option<i64>, DbError> {
        let row = sqlite_query_scalar_unchecked!(
            "SELECT telegram_chat_id FROM users WHERE id = $1",
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;
        Ok(row.flatten())
    }

    async fn get_password_reset_info(
        &self,
        email: &str,
    ) -> Result<Option<tranquil_db_traits::PasswordResetInfo>, DbError> {
        let row = sqlite_query_unchecked!(
            "SELECT password_reset_code, password_reset_code_expires_at FROM users WHERE email = $1",
            email
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        row.map(|r| {
            Ok(tranquil_db_traits::PasswordResetInfo {
                code: r.password_reset_code,
                expires_at: parse_optional_timestamp(r.password_reset_code_expires_at)?,
            })
        })
        .transpose()
    }

    async fn enable_totp_verified(
        &self,
        did: &Did,
        encrypted_secret: &[u8],
    ) -> Result<(), DbError> {
        sqlite_query!(r#"INSERT INTO user_totp (did, secret_encrypted, encryption_version, verified, created_at)
               VALUES ($1, $2, 1, TRUE, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
               ON CONFLICT (did) DO UPDATE SET secret_encrypted = $2, verified = TRUE"#,
            query_arg(did.to_string()),
            encrypted_secret
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn set_two_factor_enabled(&self, did: &Did, enabled: bool) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE users SET two_factor_enabled = $1 WHERE did = $2",
            enabled,
            query_arg(did.to_string())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(())
    }

    async fn expire_password_reset_code(&self, email: &str) -> Result<(), DbError> {
        sqlite_query!(
            "UPDATE users SET password_reset_code_expires_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') - 3600 WHERE email = $1",
            email
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlite_error)?;

        Ok(())
    }
}
