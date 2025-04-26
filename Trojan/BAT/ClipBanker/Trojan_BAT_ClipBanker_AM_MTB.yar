
rule Trojan_BAT_ClipBanker_AM_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {02 28 04 00 00 0a 0a 73 ?? 00 00 0a 28 ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 28 ?? 00 00 0a 0b 73 ?? 00 00 0a 25 07 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 25 6f ?? 00 00 0a 06 16 06 8e 69 6f ?? 00 00 0a 0c 6f ?? 00 00 0a 28 ?? 00 00 0a 08 } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {43 6f 6d 70 75 74 65 48 61 73 68 } //1 ComputeHash
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}