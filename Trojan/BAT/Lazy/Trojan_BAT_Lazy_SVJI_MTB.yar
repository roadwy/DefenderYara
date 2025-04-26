
rule Trojan_BAT_Lazy_SVJI_MTB{
	meta:
		description = "Trojan:BAT/Lazy.SVJI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {09 08 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 04 16 2d 0e 2b 21 2b 23 16 2b 23 8e 69 6f ?? 00 00 0a 73 ?? 00 00 0a 25 09 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05 de 30 } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}