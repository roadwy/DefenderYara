
rule Trojan_BAT_Lokibot_PSAP_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.PSAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {1a 59 28 26 00 00 0a 11 07 20 52 79 e2 89 5a 20 1d 7b 68 9d 61 38 a9 fd ff ff 28 27 00 00 0a 7e 01 00 00 04 02 08 6f 28 00 00 0a 28 29 00 00 0a a5 01 00 00 1b 0b 11 07 20 05 2a c9 ad 5a 20 ca ef 63 1d 61 38 7a fd ff ff 11 07 20 2f e6 d3 14 5a 20 82 e7 a4 08 61 38 67 fd ff ff } //5
		$a_01_1 = {78 7a 47 78 5a 61 38 } //1 xzGxZa8
		$a_01_2 = {41 6d 37 44 25 26 } //1 Am7D%&
		$a_01_3 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 MD5CryptoServiceProvider
		$a_01_4 = {44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 DESCryptoServiceProvider
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}