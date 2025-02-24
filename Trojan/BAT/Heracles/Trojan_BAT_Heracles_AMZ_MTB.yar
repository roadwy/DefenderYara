
rule Trojan_BAT_Heracles_AMZ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 00 11 00 6f ?? 00 00 0a 11 00 6f ?? 00 00 0a 6f ?? 00 00 0a 13 01 38 } //3
		$a_80_1 = {47 5a 69 70 53 74 72 65 61 6d } //GZipStream  1
		$a_80_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  1
	condition:
		((#a_03_0  & 1)*3+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=5
 
}