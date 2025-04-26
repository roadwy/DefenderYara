
rule Trojan_BAT_DarkTortilla_SK_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 06 14 6f 44 01 00 0a 00 00 11 06 6f 9e 02 00 0a 11 05 fe 04 13 0a 11 0a 2d e5 } //2
		$a_81_1 = {48 61 63 72 61 6a 69 71 2e 52 65 73 6f 75 72 63 65 73 } //2 Hacrajiq.Resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}