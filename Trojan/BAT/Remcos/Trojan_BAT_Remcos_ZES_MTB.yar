
rule Trojan_BAT_Remcos_ZES_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ZES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 13 01 38 ?? 01 00 00 00 11 02 20 00 01 00 00 6f ?? 00 00 0a 38 ?? 00 00 00 11 02 11 00 6f ?? 00 00 0a 38 ?? 00 00 00 11 02 11 01 6f ?? 00 00 0a 38 ?? 00 00 00 11 02 6f ?? 00 00 0a 13 03 38 ?? 00 00 00 00 02 73 ?? 00 00 0a 13 04 38 ?? 00 00 00 00 11 04 11 03 16 } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}