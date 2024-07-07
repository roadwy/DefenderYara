
rule TrojanDownloader_O97M_Dridex_PRXY_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.PRXY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 42 3e 62 53 5a 3a 2f 2f 73 69 65 72 72 61 69 6d 6f 76 65 69 73 2e 63 6f 6d 2e 62 72 2f 6d 61 6e 61 67 65 72 2f 62 42 3e 62 53 5a 6f 77 65 72 5f 63 6f 6d 70 6f 6e 65 6e 74 73 2f 62 6f 6f 74 73 74 72 61 70 2f 42 3e 62 53 5a 6c 65 73 73 2f 6d 69 78 69 6e 73 2f 42 70 5a 62 50 64 38 6d 59 30 2e 70 68 70 22 2c } //1 = Replace("httpsB>bSZ://sierraimoveis.com.br/manager/bB>bSZower_components/bootstrap/B>bSZless/mixins/BpZbPd8mY0.php",
		$a_01_1 = {3d 20 4d 69 64 28 22 55 40 72 29 4e 3c 4e 2b 79 20 26 5e 42 69 71 68 74 74 70 73 3a 2f 2f 73 74 65 72 69 67 6c 61 73 73 2e 73 74 69 67 6d 61 74 69 6e 65 73 61 66 72 69 63 61 2e 6f 72 67 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 73 6f 64 69 75 6d 5f 63 6f 6d 70 61 74 2f 6e 61 6d 65 73 70 61 63 65 64 2f 43 6f 72 65 2f 43 68 61 43 68 61 32 30 2f 4b 49 54 44 6c 43 51 48 56 79 49 2e 70 68 70 } //1 = Mid("U@r)N<N+y &^Biqhttps://steriglass.stigmatinesafrica.org/wp-includes/sodium_compat/namespaced/Core/ChaCha20/KITDlCQHVyI.php
		$a_01_2 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 57 47 2c 41 6e 33 2f 77 77 77 2e 57 47 2c 41 6e 33 6b 57 47 2c 41 6e 33 6d 67 66 6f 6f 64 73 2e 63 6f 6d 2e 62 72 2f 70 6f 73 74 57 47 2c 41 6e 33 73 2f 4f 5a 6a 58 57 47 2c 41 6e 33 6e 71 77 48 6c 56 2e 70 68 70 22 2c } //1 = Replace("https:/WG,An3/www.WG,An3kWG,An3mgfoods.com.br/postWG,An3s/OZjXWG,An3nqwHlV.php",
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}