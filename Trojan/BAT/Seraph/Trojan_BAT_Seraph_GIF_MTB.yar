
rule Trojan_BAT_Seraph_GIF_MTB{
	meta:
		description = "Trojan:BAT/Seraph.GIF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {32 30 38 2e 36 37 2e 31 30 37 2e 31 34 36 } //208.67.107.146  1
		$a_01_1 = {4d 76 6b 67 79 7a 68 65 } //1 Mvkgyzhe
		$a_01_2 = {55 67 75 70 6e 70 } //1 Ugupnp
		$a_01_3 = {53 69 65 6c 78 67 } //1 Sielxg
		$a_01_4 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_5 = {41 78 64 6d 73 61 79 78 } //1 Axdmsayx
	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}