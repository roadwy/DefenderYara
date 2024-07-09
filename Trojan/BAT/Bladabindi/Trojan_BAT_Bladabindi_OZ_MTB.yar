
rule Trojan_BAT_Bladabindi_OZ_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.OZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_02_0 = {0a 13 07 11 07 16 73 ?? ?? ?? 0a 13 06 1a 8d ?? ?? ?? 01 13 05 11 07 11 07 6f ?? ?? ?? 0a 1b 6a da 6f ?? ?? ?? 0a 11 07 11 05 16 1a 6f ?? ?? ?? 0a 26 11 05 16 28 ?? ?? ?? 0a 13 08 11 07 16 6a 6f ?? ?? ?? 0a 11 08 17 da 17 d6 8d ?? ?? ?? 01 13 04 11 06 11 04 16 11 08 } //10
		$a_80_1 = {54 6f 41 72 72 61 79 } //ToArray  1
		$a_80_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  1
		$a_80_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  1
		$a_80_4 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //MD5CryptoServiceProvider  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=14
 
}