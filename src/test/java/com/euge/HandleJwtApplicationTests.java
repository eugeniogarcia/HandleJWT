package com.euge;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.Key;
import java.util.Calendar;
import java.util.Date;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.MacProvider;

@RunWith(SpringRunner.class)
@SpringBootTest
public class HandleJwtApplicationTests {

	private static String clavePublicaOK,clavePublicaKO_validformat_not_matching_private_key,
	clavePublicaKO_wrongformat,clavePrivada,clavePrivada_2,clavePublica_2;
	private static String JWT_HS512_simetrico,JWT;
	private static Key key_HS512;
	
	private static handleJWT miGestorJWT=new handleJWT();
	
	@BeforeClass
	public static void preparaJWT() throws Exception {
	    clavePublicaOK="-----BEGIN CERTIFICATE-----\r\n" + 
	    		"MIIDmDCCAoACCQDzrizHabNcjTANBgkqhkiG9w0BAQsFADCBjTELMAkGA1UEBhMC\r\n" + 
	    		"Q0gxDTALBgNVBAgMBEJFUk4xDTALBgNVBAcMBEJFUk4xDDAKBgNVBAoMA09DRTEM\r\n" + 
	    		"MAoGA1UECwwDT0NFMRcwFQYDVQQDDA5FVUdFTklPIEdBUkNJQTErMCkGCSqGSIb3\r\n" + 
	    		"DQEJARYcRVVHRU5JTy5HQVJDSUExQFNXSVNTQ09NLkNPTTAeFw0xODA0MTcxNjA0\r\n" + 
	    		"MjRaFw0xODA1MTcxNjA0MjRaMIGNMQswCQYDVQQGEwJDSDENMAsGA1UECAwEQkVS\r\n" + 
	    		"TjENMAsGA1UEBwwEQkVSTjEMMAoGA1UECgwDT0NFMQwwCgYDVQQLDANPQ0UxFzAV\r\n" + 
	    		"BgNVBAMMDkVVR0VOSU8gR0FSQ0lBMSswKQYJKoZIhvcNAQkBFhxFVUdFTklPLkdB\r\n" + 
	    		"UkNJQTFAU1dJU1NDT00uQ09NMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\r\n" + 
	    		"AQEA0+3oMYz0LL0lgxSb+cPuYqjJZKfiJWs25SfLIUK8bdPJJVDfrOMotT0Nrkl8\r\n" + 
	    		"ysYdUddHL18qSdrkrI5D+0VEtjKIYE/NuYu+A0lt5+D8B2oI/9HXvbRAUWmgj0es\r\n" + 
	    		"LRgj51PJi+DYCeFnTzKcA7h2HFGxlzPJ4y32wmlcV24DxT8bwKoNBzvfTdbw9yN+\r\n" + 
	    		"t8KXWR0BEd3Q66hTO65wL9OGw5/XaGkA2GEwPdRKLxjyqj21jqgXjoYtA9FiPbr/\r\n" + 
	    		"n/zZ/5cmS/DA3scGToEWvvC7gA/ZC4N3mGn51oX1zIexzQWVoEOSl97hEoklncnM\r\n" + 
	    		"eJO1l9fL34aIhoheaiD5c3CYfQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQB7pcgb\r\n" + 
	    		"V/pILe15hIvNOde6Ep2fSgMmlb7QyYfTE7DErnvSpbS23vgvXrHLvDQq9O0S3ocO\r\n" + 
	    		"hVnKNThwUzpQkbZsnPsUkr3G9aHxNRxFOfTSEc6jVEVWNYH9nBmnUJOtrMUI7isX\r\n" + 
	    		"nY0rPP81XQ5KdiHhhcdUVb8KMblEry6UK7yUJ3OXBRFtHXlUQmsop8ta3mv/NLht\r\n" + 
	    		"DhjRbTaL1wdsTZMKl5vpao+g+F+nlr5mtVdH2MicuAyLycPwEITtD0PVPHrWACrA\r\n" + 
	    		"4VSKNojPWcxOwnjCAjFS9wDeDE0lHXQXyux4eol7ZajGP5BulU5tIASNwZFFBueE\r\n" + 
	    		"bqTptITggukMi4r5\r\n" + 
	    		"-----END CERTIFICATE-----";

	    clavePublicaKO_wrongformat="-----BEGIN CERTIFICATE-----\r\n" + 
	    		"EUGENIOCAoACCQDzrizHabNcjTANBgkqhkiG9w0BAQsFADCBjTELMAkGA1UEBhMC\r\n" + 
	    		"Q0gxDTALBgNVBAgMBEJFUk4xDTALBgNVBAcMBEJFUk4xDDAKBgNVBAoMA09DRTEM\r\n" + 
	    		"MAoGA1UECwwDT0NFMRcwFQYDVQQDDA5FVUdFTklPIEdBUkNJQTErMCkGCSqGSIb3\r\n" + 
	    		"DQEJARYcRVVHRU5JTy5HQVJDSUExQFNXSVNTQ09NLkNPTTAeFw0xODA0MTcxNjA0\r\n" + 
	    		"MjRaFw0xODA1MTcxNjA0MjRaMIGNMQswCQYDVQQGEwJDSDENMAsGA1UECAwEQkVS\r\n" + 
	    		"TjENMAsGA1UEBwwEQkVSTjEMMAoGA1UECgwDT0NFMQwwCgYDVQQLDANPQ0UxFzAV\r\n" + 
	    		"BgNVBAMMDkVVR0VOSU8gR0FSQ0lBMSswKQYJKoZIhvcNAQkBFhxFVUdFTklPLkdB\r\n" + 
	    		"UkNJQTFAU1dJU1NDT00uQ09NMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\r\n" + 
	    		"AQEA0+3oMYz0LL0lgxSb+cPuYqjJZKfiJWs25SfLIUK8bdPJJVDfrOMotT0Nrkl8\r\n" + 
	    		"ysYdUddHL18qSdrkrI5D+0VEtjKIYE/NuYu+A0lt5+D8B2oI/9HXvbRAUWmgj0es\r\n" + 
	    		"LRgj51PJi+DYCeFnTzKcA7h2HFGxlzPJ4y32wmlcV24DxT8bwKoNBzvfTdbw9yN+\r\n" + 
	    		"t8KXWR0BEd3Q66hTO65wL9OGw5/XaGkA2GEwPdRKLxjyqj21jqgXjoYtA9FiPbr/\r\n" + 
	    		"n/zZ/5cmS/DA3scGToEWvvC7gA/ZC4N3mGn51oX1zIexzQWVoEOSl97hEoklncnM\r\n" + 
	    		"eJO1l9fL34aIhoheaiD5c3CYfQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQB7pcgb\r\n" + 
	    		"V/pILe15hIvNOde6Ep2fSgMmlb7QyYfTE7DErnvSpbS23vgvXrHLvDQq9O0S3ocO\r\n" + 
	    		"hVnKNThwUzpQkbZsnPsUkr3G9aHxNRxFOfTSEc6jVEVWNYH9nBmnUJOtrMUI7isX\r\n" + 
	    		"nY0rPP81XQ5KdiHhhcdUVb8KMblEry6UK7yUJ3OXBRFtHXlUQmsop8ta3mv/NLht\r\n" + 
	    		"DhjRbTaL1wdsTZMKl5vpao+g+F+nlr5mtVdH2MicuAyLycPwEITtD0PVPHrWACrA\r\n" + 
	    		"4VSKNojPWcxOwnjCAjFS9wDeDE0lHXQXyux4eol7ZajGP5BulU5tIASNwZFFBueE\r\n" + 
	    		"bqTptITggukMi4r5\r\n" + 
	    		"-----END CERTIFICATE-----";
	    
	    clavePublicaKO_validformat_not_matching_private_key="-----BEGIN CERTIFICATE-----\n" + 
	    		"MIIDZjCCAk6gAwIBAgIGAUk84f/eMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYT\n" + 
	    		"AmNoMR4wHAYDVQQKDBVTd2lzc2NvbSAoU2Nod2VpeikgQUcxMzAxBgNVBAMMKm5l\n" + 
	    		"dmlzQWRtaW4gQ0EgKHZpbWFwZ2V0LW52YWQxaS5pdC5id25zLmNoKTAeFw0xNDEw\n" + 
	    		"MjMxMjAxMTlaFw0yNDEwMjMxMjAxMjRaMEIxCzAJBgNVBAYTAmNoMR4wHAYDVQQK\n" + 
	    		"DBVTd2lzc2NvbSAoU2Nod2VpeikgQUcxEzARBgNVBAMMCmF1dGhTaWduZXIwggEi\n" + 
	    		"MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDtWAPtghPPgyWzGEdMNcsB0B2j\n" + 
	    		"KU02hY6K4/ao4WaB2r14ShkqouWjgFlFcKH4w6exW2pYE1544MOqY00NmDnvlnvj\n" + 
	    		"shfxeXxLqeYYUJ8E4lujB5Y1bou0OchXADrLVA9YGjxsvEv/qOdJkHdN9MF9fY8A\n" + 
	    		"JoVgO+sTEXR7iNyi5KHxsrusW3DoJ8BrZ6TgEEfZIVZxgUeROcezkCzExHxQgPsc\n" + 
	    		"rHAUwwxdU42Etgiblq5hcu4B+ZfV+4dj68y1xyDJtj6nZZs6g/iJ+AD93zXj4wcu\n" + 
	    		"46imFgGB1PbzQQUzDJ+fqm+MvwPDQ8DJL5HXZOSVGuBBRwe2SlWWMdXEU2N/AgMB\n" + 
	    		"AAGjQjBAMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgSwMCAGA1UdJQEB/wQW\n" + 
	    		"MBQGCCsGAQUFBwMBBggrBgEFBQcDAjANBgkqhkiG9w0BAQUFAAOCAQEAIyoinlAc\n" + 
	    		"NwgNH7x+48itUB2SWc/FC/ie8I+gdWMthI+gdcpbZHU+ODGZYvyMO+j3exm9sNni\n" + 
	    		"Uz8Syx88tLOJLhRxBduGq8if+JcfS4WFn83j3beMir6eT0y4MJKXGWISc6VUlV2g\n" + 
	    		"bTlnbJoXPDFWmT4ixAll4qmsw+9Lckrh8jjUgBRKs2WWoKuVD1HXUpLOttmVwYwt\n" + 
	    		"nxutbz6bqbsoA68juD43k4IkYF0UrUm0dDAGo+GkbdlcvUQi5sF7sfgHp0jSFueg\n" + 
	    		"RQr1y+rQ/7UM6BWhUT1xA03udBwz2XXYfxqZ45osko107FJzd0rBmOza1kgaOzW+\n" + 
	    		"batiAKvKrAJNWg==\n" + 
	    		"-----END CERTIFICATE-----";

	    clavePublica_2="-----BEGIN CERTIFICATE-----\n" + 
	    		"MIIDlDCCAnwCCQChl6SIrSGArTANBgkqhkiG9w0BAQsFADCBizELMAkGA1UEBhMC\n" + 
	    		"Q0gxDTALBgNVBAgMBEJFUk4xDTALBgNVBAcMBEJFUk4xETAPBgNVBAoMCFNXSVNT\n" + 
	    		"Q09NMQwwCgYDVQQLDANPQ0UxEDAOBgNVBAMMB0VVR0VOSU8xKzApBgkqhkiG9w0B\n" + 
	    		"CQEWHEVVR0VOSU8uR0FSQ0lBMUBTV0lTU0NPTS5DT00wHhcNMTgwNDE4MDg0NjU5\n" + 
	    		"WhcNMTgwNTE4MDg0NjU5WjCBizELMAkGA1UEBhMCQ0gxDTALBgNVBAgMBEJFUk4x\n" + 
	    		"DTALBgNVBAcMBEJFUk4xETAPBgNVBAoMCFNXSVNTQ09NMQwwCgYDVQQLDANPQ0Ux\n" + 
	    		"EDAOBgNVBAMMB0VVR0VOSU8xKzApBgkqhkiG9w0BCQEWHEVVR0VOSU8uR0FSQ0lB\n" + 
	    		"MUBTV0lTU0NPTS5DT00wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDR\n" + 
	    		"RXAqN8Hrz2JVO9zm72K5by6YM8rDbCXBWSXA+QQD2FgRV+rYK4vfGlbXwo6ZYLoJ\n" + 
	    		"U09O+Nr7XpMKu/tcFr3SOXLsQaOTHTE79/nlXStQ5NPl7XXom9UROaL2lXtRiV2g\n" + 
	    		"dwhhi/IXjvOm/kAhu8FCftlDiTiOJ1i58tEgjmf7WyXgIJuMgf9FBPylLi4LFpWJ\n" + 
	    		"IlyTMiJEOJyDlosiD9LAGldqTLKAhip2g74QNQ6ZFx68T19pxeV/fj9TD0fEU3Jr\n" + 
	    		"YSE02VF07G6uv5ZskIsRfGRlVItfE2MgU/Six179MpLNDfs6XI47eSZXVz9Y9xR4\n" + 
	    		"qcfNQB/U3PWOsxJOkLitAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAHxI20SyGZzC\n" + 
	    		"9wBBEDTk/fbl581aq8dVnIN7auSWJbAQd7q2Ims2KAaLLnvD+O/DnATDkd9m6M6q\n" + 
	    		"Y3VBaSWFTGnxZAdEbwyt2kxX7+tLJI73ZQaXZRDA+lioLXGastF5ZQ9flYnXxUTR\n" + 
	    		"Tb/QyH6zVrIfdZ92DhjI7H8+sye2WDkUUbbDOee/m6FkvIAZfo8OjXjo7VSWMzYk\n" + 
	    		"1a2aJWNuAGwdvXnzfphOgVlG46iklnoyC9Tf64B5neVFOrWSM9uSHttl8Bk/W5mi\n" + 
	    		"P9+vox3vO6IcQVHBHezjOvM2iTrYlE5+ln7qvVrUF3qyYQDh9kuY/DB8v01DFN4M\n" + 
	    		"KLPmLzJEGKw=\n" + 
	    		"-----END CERTIFICATE-----";
	    		
        clavePrivada="-----BEGIN PRIVATE KEY-----\r\n" + 
        		"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDT7egxjPQsvSWD\r\n" + 
        		"FJv5w+5iqMlkp+IlazblJ8shQrxt08klUN+s4yi1PQ2uSXzKxh1R10cvXypJ2uSs\r\n" + 
        		"jkP7RUS2MohgT825i74DSW3n4PwHagj/0de9tEBRaaCPR6wtGCPnU8mL4NgJ4WdP\r\n" + 
        		"MpwDuHYcUbGXM8njLfbCaVxXbgPFPxvAqg0HO99N1vD3I363wpdZHQER3dDrqFM7\r\n" + 
        		"rnAv04bDn9doaQDYYTA91EovGPKqPbWOqBeOhi0D0WI9uv+f/Nn/lyZL8MDexwZO\r\n" + 
        		"gRa+8LuAD9kLg3eYafnWhfXMh7HNBZWgQ5KX3uESiSWdycx4k7WX18vfhoiGiF5q\r\n" + 
        		"IPlzcJh9AgMBAAECggEAA6NQ2hDmXCI/E5n193qii/UDyAONwUCu544gUYjYvTXm\r\n" + 
        		"fQp/XHNlzn6mzngaeUyfUjlU0n5atnvYcxHaHuUYgdwqNSUJjgbVEy9egJ1/Fg1+\r\n" + 
        		"7A1JG8uNUxhyFiOP1BJXA3CPxCPu8XR6FoTy4ql29ZN9bfAIpiqy0rGGUUXlMKyV\r\n" + 
        		"pE//zZ3bBhC5B0UIoRGQKl0cAsD4/Q4rZN9eJWzN4BldW5MpKrk/qzboxm6iJRIP\r\n" + 
        		"+EiWhiZvRlrBekmo8t5UzvBOTVep+/MzpY1k3ejzWy2O0Ecl9IgHKOC6an6W/eTz\r\n" + 
        		"nlxERyNEswyWF471jEqdOsG13TeFsjGRmpkDX/M0gQKBgQD5j1s/MMEso7khQg7M\r\n" + 
        		"vQ5STsXByUYmHvSuAMd2gWkJ53qPeHFf4lLy6x1S+9P9iJKgIvbqCtaDII4qmGLb\r\n" + 
        		"PALKOx+bdDd7oKLiyvIgiOquPlRHa2E0Z+bDTJcSHHpkj3bP4cfVrPNd4YXZtfnx\r\n" + 
        		"zjotnoMwU1djPxrZdaUdvV2QYQKBgQDZZfRwLB4qJjEh20vJZO3JuNA4tzAwJAwP\r\n" + 
        		"8a7+DVFjZU6XmHfNIhtZNQA9qjAeYu35zseFo1NoLBLJRYMYqjpOSKaXcDGSsw/6\r\n" + 
        		"Yd73R5ZC7j1HBlCheGyHHWooW9rmuvQlPxQOEB1iWehprq8P2zy9l7kLv8BYiy3Z\r\n" + 
        		"kVtS9W4tnQKBgQDxwugxqkiptx5E0trFiy0RnZBE8HjNu1VsMAMLkcixOJdp39Nt\r\n" + 
        		"gTK8c/rfhmjTB3iMO/MZvlAbjfFL4H58RoGpamdvUMHjOTYzIUo5LIq1LFq3KZZs\r\n" + 
        		"j29lqY/8kqwbOURvlRnjrX3CaBUkWP9/OjrwMMyEh2h0FBEts6O20NmQYQKBgGH6\r\n" + 
        		"ynU33QyAFAq/TGPjQix1SBsXrPc1d95DveuwUusqQIagZ/YjFhJZiddA+djoG3tI\r\n" + 
        		"D7KSTsgXfQwLcS9PoWGg6rw8C4ujemMNczEdqYJW33VASlzL6pXm0u6Hn5v3zItw\r\n" + 
        		"53gDGUs3XEEtQqcx1ylX1UWPUYBWkf6JvZAhH1wdAoGALZG8F9T6lmfQ21d7nDzW\r\n" + 
        		"Y1SEXj4lrr3TnIxRJEC9+h2x2gPvgJIWnAa1gqyQ74nMW7bGiF+tQtcpbunNJ+i1\r\n" + 
        		"TmmVKBQoXXpVUhLroNYDsQ/CHp0lpuorrmyB/2uWvivJkGSE9UGz3rEZmfVVKcGL\r\n" + 
        		"vTBcUpuxx/yqoejhgvhFTf8=\r\n" + 
        		"-----END PRIVATE KEY-----";
        
        clavePrivada_2="-----BEGIN PRIVATE KEY-----\n" + 
        		"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDRRXAqN8Hrz2JV\n" + 
        		"O9zm72K5by6YM8rDbCXBWSXA+QQD2FgRV+rYK4vfGlbXwo6ZYLoJU09O+Nr7XpMK\n" + 
        		"u/tcFr3SOXLsQaOTHTE79/nlXStQ5NPl7XXom9UROaL2lXtRiV2gdwhhi/IXjvOm\n" + 
        		"/kAhu8FCftlDiTiOJ1i58tEgjmf7WyXgIJuMgf9FBPylLi4LFpWJIlyTMiJEOJyD\n" + 
        		"losiD9LAGldqTLKAhip2g74QNQ6ZFx68T19pxeV/fj9TD0fEU3JrYSE02VF07G6u\n" + 
        		"v5ZskIsRfGRlVItfE2MgU/Six179MpLNDfs6XI47eSZXVz9Y9xR4qcfNQB/U3PWO\n" + 
        		"sxJOkLitAgMBAAECggEAdclmi2ycqnQsfZrXB+hfIc4RZLtp+bpqObxKgqXl+6AO\n" + 
        		"WZypYwiHjohNrt0j0/JcY5lPfzyUTH17t8P8g2WNa8DIDXAYeFoq9vzo248oLTzO\n" + 
        		"g5C3F7h2IV7WeYHDSi5N016MChNxrI7aVvit8g6yhRHOibO3cFN3HhosWO2uWwt6\n" + 
        		"uuCINGVpin6X/4BBkvzSHWT8dqt2tL28vp0lv1CkxGscxjSI6uAZ/t4khfeXhWfd\n" + 
        		"FHAhdB1xBkGvQXWM1EYjUqT9q/ZQBNBP0jLPF5VRdKjWzkI0saNVqVJbj88uG3jf\n" + 
        		"VBWBM4LgZRKBX2A3zu4kBfJ3rtzQsx3whL82UTcowQKBgQDv1/DFW8fpeahsIDi+\n" + 
        		"ti+f6Oej7ZGh/V6c8JTchkx3LU9BcSAEuPD+uARKCyfLp+l/X2QBeh15u1Vgr0bU\n" + 
        		"de1T8tSyvwY9Opqy98fRd0bea3QvpevjY7uQJXFxTBUJxd0QAqITj7offr6yEkxQ\n" + 
        		"w84V6mk7y56kmzx5vrMSmNU/sQKBgQDfXki69TRF8g8IeL4LmbtDiLyEKxCmlbO6\n" + 
        		"KCLxiuqvz+UYlmogMQYS1E9HdqPNlbRwE++J6DKwGcgn19XQqLClD+Hsr/gKzWDE\n" + 
        		"oRTPzYZoNlX3gCD3EostzP1deqtEtwhDCgPSc1QEUV9VlplM2WVMHibppaSfDrDf\n" + 
        		"LSGaOoOjvQKBgQCSQUAVWW6CtSk7Jjr0MOzBuqjmkcwo1/SGBz7/avXeBsc5xN4d\n" + 
        		"gxmSemxDKqJN0krU3TqCnBC1VsMtfjTXAkKC2qVRiqMnW0FSuT4kQXP51dS36Zn6\n" + 
        		"w6pwsCSJTjfWCc5QIQrsmsyIwCVROU9IQN6/Bn69c+F9xxwNsXhJcuE3QQKBgEpI\n" + 
        		"jcF3OGomhO9ZUEKFXqyn9aGyvLfZw0qefHh9rWzIo7TYmPSZuR5b8v2eK/170uUP\n" + 
        		"DDN9wBWmjVUKx3W8E/rg3E6des0E3jCmLUiqXg+cOly0BMKGLTkPGheTaw/QGvRI\n" + 
        		"iVrctc01zpGlIthW2ARHZsN/Lc8j0Jh35tvmp861AoGAEGrhg7DlVj3segXPq0i0\n" + 
        		"0UhVCJNuOP5rYaJgpmn8zR55nNvIEjTZl6OPXODBZsf9nj9hpIpsnx5WlMnPMGL5\n" + 
        		"3m/VgVwhogp0t4xCsdjpSOQq6ZwiqW733Z14Lq618e9e95KAlWLb7IqJdBTkwx8T\n" + 
        		"Au4QXhL+Qx2pUsueuGG/Ark=\n" + 
        		"-----END PRIVATE KEY-----";
        
        //Usa un token con un algoritmo de clave simetrica.
		key_HS512= MacProvider.generateKey();
		JWT_HS512_simetrico=miGestorJWT.createJWT(key_HS512,SignatureAlgorithm.HS512,"Lionel Andres", "Messi","983397696","messi@fcb.com","en","20","30","my subject");

		//Crea un token con el algoritmo RS256. Este usa una clave privada
		JWT=miGestorJWT.createJWT(miGestorJWT.loadPrivateKey(clavePrivada),SignatureAlgorithm.RS256,"Lionel Andres", "Messi","983397696","messi@fcb.com","en","20","30","my subject");

	}

	@Test
	public void checkJWT_simetrico() {
		assertTrue(miGestorJWT.checkJWT(key_HS512, JWT_HS512_simetrico));
		Claims entradasJWT=Jwts.parser().setSigningKey(key_HS512).parseClaimsJws(JWT_HS512_simetrico).getBody();
		assertEquals("my subject",entradasJWT.getSubject());
		assertEquals("Lionel Andres",(String)entradasJWT.get("given_name"));
	}
	
	@Test
	public void checkJWT_rightSignature() throws Exception {
		Key key=miGestorJWT.loadPublicKey(clavePublicaOK);
		assertTrue(miGestorJWT.checkJWT(key, JWT));
		Claims entradasJWT=Jwts.parser().setSigningKey(key).parseClaimsJws(JWT).getBody();
		assertEquals("my subject",entradasJWT.getSubject());
		assertEquals("Lionel Andres",(String)entradasJWT.get("given_name"));
	}

	@Test
	public void checkJWT_rightSignature_expired() throws Exception {
		Calendar cal = Calendar.getInstance(); // creates calendar
	    cal.setTime(new Date()); // sets calendar time/date
	    cal.add(Calendar.HOUR_OF_DAY,1); // adds one hour
	    cal.add(Calendar.MINUTE,1);
	    
		Key key=miGestorJWT.loadPublicKey(clavePublicaOK);
		assertTrue(miGestorJWT.checkJWT(key, JWT));
		//Claims entradasJWT = new DefaultClaims();
		Claims entradasJWT=Jwts.parser().setSigningKey(key).parseClaimsJws(JWT).getBody();
		assertEquals("my subject",entradasJWT.getSubject());
		assertTrue(cal.getTime().after(entradasJWT.getExpiration()));
	}
	
	@Test
	public void checkJWT_wrongFormatSignature() throws Exception {
		Key key=miGestorJWT.loadPublicKey(clavePublicaKO_wrongformat);
		assertNull(key);
	}

	@Test
	public void checkJWT_wrongSignature() throws Exception {
		Key key=miGestorJWT.loadPublicKey(clavePublicaKO_validformat_not_matching_private_key);
		assertTrue(!miGestorJWT.checkJWT(key, JWT));
	}

}
