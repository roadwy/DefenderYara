
rule Trojan_BAT_PureLogs_ZDU_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.ZDU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 37 2b 39 15 2d 39 26 26 2b 3c 2b 3e 2b 3f 11 04 6f ?? 00 00 0a 13 05 72 13 01 00 70 13 06 11 05 06 16 06 8e 69 6f ?? 00 00 0a 13 07 11 07 03 11 06 28 ?? 00 00 06 de 28 11 04 2b c5 08 2b c4 6f ?? 00 00 0a 2b c2 11 04 2b c0 09 2b bf 6f ?? 00 00 0a 2b ba } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}