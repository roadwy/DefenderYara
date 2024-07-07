
rule Trojan_BAT_CoinMiner_GDN_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.GDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 58 4e 55 62 4c 37 66 6d 57 78 68 52 33 66 33 55 66 } //1 PXNUbL7fmWxhR3f3Uf
		$a_01_1 = {76 66 74 30 6b 49 42 51 36 34 4c 4d 6f 63 39 66 78 77 } //1 vft0kIBQ64LMoc9fxw
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_3 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 TripleDESCryptoServiceProvider
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}