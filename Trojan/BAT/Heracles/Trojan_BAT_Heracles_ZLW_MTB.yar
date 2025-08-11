
rule Trojan_BAT_Heracles_ZLW_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ZLW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 16 06 8e 69 6f ?? 00 00 0a 0c de 47 07 2b d5 28 ?? 01 00 0a 2b d5 6f ?? 01 00 0a 2b d0 07 2b cf 28 ?? 01 00 0a 2b cf 6f ?? 01 00 0a 2b ca 07 2b cc 6f ?? 01 00 0a 2b c7 } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}