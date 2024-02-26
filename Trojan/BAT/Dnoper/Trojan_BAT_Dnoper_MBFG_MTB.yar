
rule Trojan_BAT_Dnoper_MBFG_MTB{
	meta:
		description = "Trojan:BAT/Dnoper.MBFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 06 07 6f 90 01 01 02 00 0a 17 73 c2 00 00 0a 25 02 16 02 8e 69 6f 90 01 01 01 00 0a 6f 90 01 01 01 00 0a 06 90 00 } //01 00 
		$a_01_1 = {74 65 44 65 63 72 79 70 74 6f 72 00 65 58 5a 48 46 46 53 71 6e 63 00 6f 53 61 } //00 00  整敄牣灹潴r塥䡚䙆煓据漀慓
	condition:
		any of ($a_*)
 
}