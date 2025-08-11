
rule Trojan_BAT_Xworm_ZSS_MTB{
	meta:
		description = "Trojan:BAT/Xworm.ZSS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {2d 01 2a 72 01 00 00 70 28 ?? 00 00 06 0a 16 0b 2b 1a 06 07 8f ?? 00 00 01 25 71 ?? 00 00 01 1f 5a 61 d2 81 ?? 00 00 01 07 17 58 0b 07 06 8e 69 32 e0 } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}