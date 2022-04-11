package server

import (
	"context"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	appconfig "github.com/kfsoftware/hlf-channel-manager/config"
	operatorv1 "github.com/kfsoftware/hlf-operator/pkg/client/clientset/versioned"

	"github.com/kfsoftware/hlf-channel-manager/gql"
	"github.com/kfsoftware/hlf-channel-manager/gql/resolvers"
	"github.com/kfsoftware/hlf-channel-manager/log"
	"github.com/kfsoftware/hlf-channel-manager/server/metrics"
	"io"
	"time"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/apollotracing"
	"github.com/99designs/gqlgen/graphql/handler/extension"
	"github.com/99designs/gqlgen/graphql/handler/lru"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/slok/go-http-metrics/metrics/prometheus"
	"github.com/slok/go-http-metrics/middleware"
	middlewarestd "github.com/slok/go-http-metrics/middleware/std"
	"net/http"
)

type MetricsRegistry interface {
	IncGraphqlRequest(statusCode int)
	ObserveGraphqlMutation(duration time.Duration)
}

type BlockchainServerOpts struct {
	Address              string
	MetricsAddress       string
	DCS                  map[string]*operatorv1.Clientset
	FabricSDK            *fabsdk.FabricSDK
	ChannelManagerConfig appconfig.HLFChannelManagerConfig
}

type BlockchainAPIServer struct {
	BlockchainServerOpts
	metrics MetricsRegistry
	stopCh  chan struct{}
}

func NewServer(ctx context.Context, opts BlockchainServerOpts) *BlockchainAPIServer {
	return &BlockchainAPIServer{
		BlockchainServerOpts: opts,
	}
}
func (a *BlockchainAPIServer) Run() {
	metricsServ := metrics.NewMetricsServer(a.MetricsAddress)
	mux, err := a.setupHttpServer()
	if err != nil {
		log.Errorf("Error setting up http server: %s", err)
		return
	}
	go func() {
		log.Infof("Server listening on %s", a.Address)
		a.checkServeErr("server", http.ListenAndServe(a.Address, mux))
	}()
	go func() {
		log.Infof("Metrics server listening on %s", a.MetricsAddress)
		a.checkServeErr("metrics", metricsServ.ListenAndServe())
	}()
	a.stopCh = make(chan struct{})
	<-a.stopCh
}

func (a *BlockchainAPIServer) setupHttpServer() (http.Handler, error) {
	serverMux := http.NewServeMux()

	config := gql.Config{
		Resolvers: &resolvers.Resolver{
			DCS:                  a.DCS,
			FabricSDK:            a.FabricSDK,
			ChannelManagerConfig: a.ChannelManagerConfig,
		},
	}
	// TODO: set up auth
	//config.Directives.HasRole = func(ctx context.Context, obj interface{}, next graphql.Resolver, role models.BlockchainRole) (interface{}, error) {
	//	if !a.AuthConfig.Enabled {
	//		return next(ctx)
	//	}
	//	user := ctx.Value("user")
	//	if user == nil {
	//		return nil, errors.New("access denied")
	//	}
	//	token, ok := user.(*jwt.Token)
	//	if !ok {
	//		return nil, errors.New("invalid user")
	//	}
	//	claims, ok := token.Claims.(jwt.MapClaims)
	//	if !ok {
	//		return nil, errors.New("invalid claims")
	//	}
	//	scope, ok := claims["scope"].(string)
	//	if !ok {
	//		return nil, errors.New("invalid scope")
	//	}
	//	scopes := strings.Split(scope, " ")
	//	var scopesToFind []string
	//	var groupsToFind []string
	//	if role == models.BlockchainRoleAdmin {
	//		scopesToFind = a.AuthConfig.AdminGroups
	//		groupsToFind = a.AuthConfig.AdminGroups
	//	} else if role == models.BlockchainRoleRead {
	//		scopesToFind = a.AuthConfig.ReadGroups
	//		groupsToFind = a.AuthConfig.AdminGroups
	//	} else {
	//		return nil, errors.Errorf("invalid role %s", role)
	//	}
	//	for _, s := range scopes {
	//		for _, g := range scopesToFind {
	//			if s == g {
	//				return next(ctx)
	//			}
	//		}
	//	}
	//	if a.AuthConfig.GroupsJWTKey != "" {
	//		groupsClaim, ok := claims[a.AuthConfig.GroupsJWTKey]
	//		if ok {
	//			groups, ok := groupsClaim.([]interface{})
	//			if ok {
	//				for _, g := range groups {
	//					for _, g2 := range groupsToFind {
	//						if g == g2 {
	//							return next(ctx)
	//						}
	//					}
	//				}
	//			}
	//		}
	//	}
	//	return nil, errors.New("access denied")
	//}
	es := gql.NewExecutableSchema(config)
	h := handler.New(es)
	h.AddTransport(transport.Options{})
	h.AddTransport(transport.GET{})
	h.AddTransport(transport.POST{})
	h.AddTransport(transport.MultipartForm{})

	h.SetQueryCache(lru.New(1000))
	h.Use(extension.Introspection{})
	h.Use(extension.AutomaticPersistedQuery{
		Cache: lru.New(100),
	})
	h.Use(apollotracing.Tracer{})
	metrics.Register()
	h.Use(metrics.Tracer{})
	// TODO: set up auth
	//jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
	//	ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
	//		iss := a.AuthConfig.Issuer
	//		checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
	//		if !checkIss {
	//			return token, errors.New("Invalid issuer.")
	//		}
	//
	//		cert, err := getPemCert(token, a.AuthConfig.JWKSUrl)
	//		if err != nil {
	//			panic(err.Error())
	//		}
	//		return cert, nil
	//	},
	//	SigningMethod:       jwt.SigningMethodRS256,
	//	CredentialsOptional: true,
	//})
	graphqlHandler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Access-Control-Allow-Origin", "*")
		writer.Header().Set("Access-Control-Allow-Credentials", "true")
		writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-Identity")
		writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT")
		h.ServeHTTP(writer, request)
	})
	serverMux.HandleFunc(
		"/graphql",
		graphqlHandler,
	)
	playgroundHandler := playground.Handler("GraphQL", "/graphql")
	serverMux.HandleFunc(
		"/playground",
		playgroundHandler,
	)
	serverMux.HandleFunc(
		"/healthz",
		func(w http.ResponseWriter, request *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"alive": true}`)
		},
	)

	mdlw := middleware.New(middleware.Config{
		Recorder: prometheus.NewRecorder(prometheus.Config{}),
	})
	httpHandler := middlewarestd.Handler("", mdlw, serverMux)
	//if a.AuthConfig.Enabled {
	//	httpHandler = jwtMiddleware.Handler(serverMux)
	//}
	return httpHandler, nil
}

//
//type Jwks struct {
//	Keys []JSONWebKeys `json:"keys"`
//}
//
//type JSONWebKeys struct {
//	Kty string   `json:"kty"`
//	Kid string   `json:"kid"`
//	Use string   `json:"use"`
//	N   string   `json:"n"`
//	E   string   `json:"e"`
//	X5c []string `json:"x5c"`
//}
//
//func getPemCert(token *jwt.Token, jwksUrl string) (*rsa.PublicKey, error) {
//	kid := token.Header["kid"].(string)
//	set, err := jwk.Fetch(context.Background(), jwksUrl)
//	if err != nil {
//		log.Printf("failed to parse JWK: %s", err)
//		return nil, err
//	}
//	k, exists := set.LookupKeyID(kid)
//	if !exists {
//		return nil, errors.Errorf("kid %s not found in jwks", kid)
//	}
//	var rawKey interface{}
//	err = k.Raw(&rawKey)
//	if !exists {
//		return nil, err
//	}
//	rsaKey, ok := rawKey.(*rsa.PublicKey)
//	if !ok {
//		return nil, errors.Errorf("kid %s not found in jwks", kid)
//	}
//	return rsaKey, nil
//}

// checkServeErr checks the error from a .Serve() call to decide if it was a graceful shutdown
func (a *BlockchainAPIServer) checkServeErr(name string, err error) {
	if err != nil {
		if a.stopCh == nil {
			// a nil stopCh indicates a graceful shutdown
			log.Infof("graceful shutdown %s: %v", name, err)
		} else {
			log.Fatalf("%s: %v", name, err)
		}
	} else {
		log.Infof("graceful shutdown %s", name)
	}
}
