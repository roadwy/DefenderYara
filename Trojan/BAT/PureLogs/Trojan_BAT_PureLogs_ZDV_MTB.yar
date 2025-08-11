
rule Trojan_BAT_PureLogs_ZDV_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.ZDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 0b de 73 20 cc 56 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 0c 20 b6 54 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 11 04 09 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05 03 20 a3 54 00 00 28 ?? 00 00 06 11 05 06 16 06 8e 69 6f ?? 00 00 0a 6f ?? 00 00 06 de 0c } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}