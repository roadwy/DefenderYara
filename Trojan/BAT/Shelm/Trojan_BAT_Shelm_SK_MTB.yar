
rule Trojan_BAT_Shelm_SK_MTB{
	meta:
		description = "Trojan:BAT/Shelm.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 09 11 86 07 11 86 93 28 15 00 00 0a 9c 00 11 86 17 58 13 86 11 86 09 8e 69 fe 04 13 87 11 87 2d de } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}