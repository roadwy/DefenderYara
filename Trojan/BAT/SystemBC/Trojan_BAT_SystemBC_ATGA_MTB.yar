
rule Trojan_BAT_SystemBC_ATGA_MTB{
	meta:
		description = "Trojan:BAT/SystemBC.ATGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 20 00 01 00 00 6f ?? 00 00 0a 08 72 ?? ?? 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 72 ?? ?? 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 } //4
		$a_03_1 = {2b 0f 2b 11 1e 2d 12 26 26 2b 15 2b 17 2b 1c de 62 11 06 2b ed 11 04 2b eb 6f ?? 00 00 0a 2b e9 11 04 2b e7 6f ?? 00 00 0a 2b e2 13 07 2b e0 } //2
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}