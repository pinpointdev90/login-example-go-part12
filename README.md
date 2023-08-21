# login-example-go-part12の目標
- ログイン時にリフレッシュトークンをcookieにセットする
- /auth/refreshの実装

## ログイン時にリフレッシュトークンをcookieにセットする

### JwtBuilder

今まではJwtBuilderはアクセストークンを作ることが役割でしたが、今回からリフレッシュトークンも作れるように改良していきます。
まずはコードを少し変更します。

auth/jwt_builder.go
```
const (
	userIDClaim      = "user_id"
	issClaim         = "login-example"
	accessSubClaim   = "access-token"
+	refreshSubClaim  = "refresh-token"
	userIDContextKey = "user_id"
)

var (
	//go:embed keys/secret.pem
	secretKey []byte
	//go:embed keys/public.pem
	publicKey []byte
	
	// アクセストークンの有効期限
	expAccess = 30 * time.Minute
+	// リフレッシュトークンの有効期限
+	expRefresh = 3 * 24 * time.Hour
)

+ type IJwtBuilder interface {
+	IJwtGenerator
+	IJwtParser
+ }

type IJwtGenerator interface {
-	GenerateToken(u *entity.User) ([]byte, error)
+	GenerateAccessToken(u *entity.User) ([]byte, error)
+	GenerateRefreshToken(u *entity.User) ([]byte, error)
}


+ func (j *JwtBuilder) GenerateAccessToken(u *entity.User) ([]byte, error) {
+ 	return j.generateJWT(u, accessSubClaim, expAccess)
+ }

+ func (j *JwtBuilder) GenerateRefreshToken(u *entity.User) ([]byte, error) {
+ 	return j.generateJWT(u, refreshSubClaim, expRefresh)
+ }

// JWTを作成する
- func (j *JwtBuilder) GenerateToken(u *entity.User) ([]byte, error) {
+ func (j *JwtBuilder) generateJWT(u *entity.User, subClaim string, exp time.Duration) ([]byte, error) {
	// JWTを作成
	tok, err := jwt.NewBuilder().
		Issuer(issClaim).
		Subject(subClaim).
		IssuedAt(time.Now()).
- 		Expiration(time.Now().Add(expAccess)).
+		Expiration(time.Now().Add(exp)).
		Claim(userIDClaim, u.ID).
		Build()
	if err != nil {
		return nil, fmt.Errorf("failed to jwt build: %w", err)
	}

	// JWTを秘密鍵でハッシュ化します。
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, j.secretKey))
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}
	return signed, nil
}
```

この変更に合わせてusecaseも変更します。

usecase/user_usecase.go
```
func (uu *userUsecase) Login(ctx context.Context, email, password string) ([]byte, error) {

	// ~~~
	
	// ユーザー情報からJWTを作成
-	tok, err := uu.jwter.GenerateToken(u)
+	tok, err := uu.jwter.GenerateAccessToken(u)
	if err != nil {
		return nil, err
	}
	return tok, nil
}
```

コードを少し修正しました。

### Usecase

usecase/user_usecase.go
```
type IUserUsecase interface {
	PreRegister(ctx context.Context, email, pw string) (*entity.User, error)
	Activate(ctx context.Context, email, token string) error
-	Login(ctx context.Context, email, password string) ([]byte, error)
+	Login(ctx context.Context, email, password string) ([]byte, *http.Cookie, error)
	Get(ctx context.Context, uid entity.UserID) (*entity.User, error)
}

// ~~~

- func NewUserUsecase(ur repository.IUserRepository, mailer mail.IMailer, jwter auth.IJwtGenerator) IUserUsecase {
+ func NewUserUsecase(ur repository.IUserRepository, mailer mail.IMailer, jwter auth.IJwtBuilder) IUserUsecase {
	return &userUsecase{ur: ur, mailer: mailer, jwter: jwter}
}

// ~~~

- func (uu *userUsecase) Login(ctx context.Context, email, password string) ([]byte, error) 
+ func (uu *userUsecase) Login(ctx context.Context, email, password string) ([]byte, *http.Cookie, error) {
	// emailからユーザー情報を取得する
	u, err := uu.ur.GetByEmail(ctx, email)
	if err != nil {
-		return nil, err
+		return nil, nil, err
	}
	// ユーザーがアクティブでないならエラー
	if !u.IsActive() {
-		return nil, errors.New("user inactive")
+		return nil, nil, errors.New("user inactive")
	}
	// ユーザーのパスワードを検証
	if err := u.Authenticate(password); err != nil {
-		return nil, err
+		return nil, nil, err
	}
	// ユーザー情報からJWTを作成
	tok, err := uu.jwter.GenerateAccessToken(u)
	if err != nil {
-		return nil, err
+		return nil, nil, err
	}

	refreshToken, err := uu.jwter.GenerateRefreshToken(u)
	if err != nil {
-		return nil, err
+		return nil, nil, err
	}
+	cookie := new(http.Cookie)
+	cookie.Name = "refresh-token"
+	cookie.Value = string(refreshToken)
+	cookie.Expires = time.Now().Add(3 * 24 * time.Hour)
+	// cookieのsame-site属性。今回は使うとしてもlocalhostからなのでStrictを指定
+	cookie.SameSite = http.SameSiteStrictMode
+	// HttpOnlyを設定することでJavaScriptでCookie操作を禁止
+	cookie.HttpOnly = true
+	// https通信のみcookieを利用する
+	// 本来はtrueに設定するべきだが、httpsは使わないので今回はなし
+	// cookie.Secure = true

	return tok, cookie, nil
}
```

### Handler

handler/user_handler.go
```
func (h *userHandler) Login(c echo.Context) error {
	
	// ~~~
	
-	tok, err := h.uu.Login(ctx, rb.Email, rb.Password)
+	tok, cookie, err := h.uu.Login(ctx, rb.Email, rb.Password)
	if err != nil {
		return err
	}

+	c.SetCookie(cookie)

	// ログイン成功、としてJWTを返す
	return c.JSON(http.StatusOK, echo.Map{
		"access_token": string(tok),
	})
}
```

これでcookieがセットされるようになりました！

### 確認しよう

実際にcookieがセットされるか確認してみましょう

```
$ curl -v -XPOST localhost:8000/api/auth/login \
        -H 'Content-Type: application/json; charset=UTF-8' \
        -H 'X-CSRF-Header: secret' \
        -d '{"email": "test-user-1@example.xyz", "password": "foobar"}
```

```
< HTTP/1.1 200 OK
< Content-Type: application/json; charset=UTF-8
< Set-Cookie: refresh-token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODg3MTgyNzAsImlhdCI6MTY4ODQ1OTA3MCwiaXNzIjoibG9naW4tZ28iLCJzdWIiOiJyZWZyZXNoLXRva2VuIiwidXNlcl9pZCI6MTAwMDA0fQ.gaLwIzYjoV-q_U-f__T1RiELwzXVpcXYuWfLSythkPDizeKJLhQxsMRj1e0D9laoJcuxaf1lr2K4qPo-NWJKRS5JQ0o1J8A80SNTc0PzbdRPkocrJ26PhSz1v5_-w7Cq8bicGcRX9L1gLZqorJYXjTA0o9My6MjKczbUFGZCJfg5WL26xktE48_SioJQszgPPu9WLuz_aB_--ShnK7xX3-DkVVdINuvrq4vC6yf-SmhA7pv25pAWmLPsTyqKjRld2xunVoBGO_bOHVpcaHceKZ_gUtthLrWRUKjkF934M2H9Kt8SDn54apfE1C_a2Rg1DwUh5HVoRLx6Za9dogoaHw; HttpOnly; Secure; SameSite=Strict
< Vary: Origin
< Date: Tue, 04 Jul 2023 08:24:30 GMT
< Content-Length: 520
```

ちゃんとSet-Cookieでrefresh-tokenがセットされてます。
JWT.IOで確認してもsubはrefresh-tokenになってますし、expも伸びてます。

## /auth/refreshの実装

### JwtBuilder

auth/jwt_builder.go
```
type IJwtParser interface {
	SetAuthToContext(c echo.Context) error
+	GetUserIDFromJWT(token []byte) (entity.UserID, error)
}
```

```
// ~~~

func (j *JwtBuilder) GetUserIDFromJWT(token []byte) (entity.UserID, error) {
	tok, err := j.parseJWT(token)
	if err != nil {
		return 0, err
	}
	id, ok := tok.Get(userIDClaim)
	if !ok {
		return 0, errors.New("failed to get user_id from token")
	}
	uid, ok := id.(float64)
	if !ok {
		return 0, fmt.Errorf("get invalid user_id: %v, %T", id, id)
	}
	return entity.UserID(uid), nil
}

func (j *JwtBuilder) parseJWT(token []byte) (jwt.Token, error) {
	tok, err := jwt.Parse(token,
		jwt.WithKey(jwa.RS256, j.publicKey),
		jwt.WithIssuer(issClaim),
		jwt.WithSubject(refreshSubClaim))
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}
	return tok, err
}
```

### Usecase

usecase/user_usecase.go
```
// ~~~

func (uu *userUsecase) Refresh(ctx context.Context, token []byte) ([]byte, error) {
	uid, err := uu.jwter.GetUserIDFromJWT(token)
	if err != nil {
		return nil, err
	}
	u, err := uu.ur.Get(ctx, uid)
	if err != nil {
		return nil, err
	}
	tok, err := uu.jwter.GenerateAccessToken(u)
	if err != nil {
		return nil, err
	}
	return tok, nil
}
```

### Handler

handler/user_handler.go
```
type IUserHandler interface {
	PreRegister(c echo.Context) error
	Activate(c echo.Context) error
	Login(c echo.Context) error
	GetMe(c echo.Context) error
+	Refresh(c echo.Context) error
}
```

```
// ~~~

func (h *userHandler) Refresh(c echo.Context) error {
	cookie, err := c.Cookie("refresh-token")
	if err != nil {
		return err
	}

	ctx := c.Request().Context()

	v := cookie.Value
	tok, err := h.uu.Refresh(ctx, []byte(v))
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, echo.Map{
		"access_token": string(tok),
	})
}
```

### Router
router.go
```
func NewRouter(db *sqlx.DB, mailer mail.IMailer, jwter *auth.JwtBuilder) *echo.Echo {
	// ~~~
	
	a := e.Group("/api/auth")
	a.POST("/register/initial", uh.PreRegister)
	a.POST("/register/complete", uh.Activate)
	a.POST("/login", uh.Login)
+	a.GET("/refresh", uh.Refresh)

	// ~~~
}
```


### 確認

毎度のごとく、本当にリフレッシュトークンからアクセストークンが取得できるか確認していきましょう。

```
curl -XGET localhost:8000/api/auth/refresh \
	-H 'X-CSRF-Header: secret' \
	-b "refresh-token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODg3MjU0MDcsImlhdCI6MTY4ODQ2NjIwNywiaXNzIjoibG9naW4tZ28iLCJzdWIiOiJyZWZyZXNoLXRva2VuIiwidXNlcl9pZCI6MTAwMDA0fQ.QFZl6jCpF1LxT8q6b2QXNsMBJGVNWQDNeQE7WbRauQ8fSsiLHco2Ed_wZ2_Nz9NktLQazvgTedeGnpIyEzXrMD9dVF5OHxDYsp0gygOaFf4rmvReOpLTJF-xRMnxzDrQ6kk0YiYDKQrfgkVHcQUoCwek3LVoCIT35N7QWDabvs5OAKshiYkLJQknM2v2jHYep5jwf0vqQexXYsegUiBCmTGu6dNAnRIT6q82b0tAZq8CTUTF7KE7_xSrc67NI333Z5OUJjJS7Gq3jnQEJgvWmYAaYgWCJImeepgKGUUqd5A-_QQ57dQBibqs_xe8JwmHWobnWx3p9tNkrdM1q7G57Q"
```

```
{"access_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODg0NzIxOTcsImlhdCI6MTY4ODQ3MDM5NywiaXNzIjoibG9naW4tZ28iLCJzdWIiOiJhY2Nlc3MtdG9rZW4iLCJ1c2VyX2lkIjoxMDAwMDR9.T-xLgnVfqu8NwsnK5IeDhLpfgcQkYKb2qtpeHUPTzY8sRs5akDWapiI98i7m5QIouXWeRhSf-rbJDCQ7bZl4nwxqPTnv85GuefluYQELc8tJCBZ5xVD7mpYBw_eFxNoFk01tmoNWJ1FaRpwLPvpo2yE-jwfd5EvSFouqeFNuNQF5vbqFYV518SA5nFviPMVVY5OBbiDD_rvsBqt4KP4ZxjGC-n5GfmPMZJccitMWf998_gOrZ-EfM3EclL4QPK433P3Il7qey5NEW8Vv7Fc6aaK8_Lhforq4AYo7TfIE3bT0_Et8O6coJjR6Dq_tZKnCn8f4XbLO3-HiCKFXej79DA"}
```

ちゃんとaccess_tokenが返ってきました！

# まとめ

今回行なった作業です

- RefreshTokenのJWTを作成
- ログイン時にcookieをセットするようにした
- /auth/refreshを実装しました。