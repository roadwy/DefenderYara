
rule Trojan_BAT_Remcos_MBCY_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MBCY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 00 72 38 03 00 70 28 90 01 01 00 00 06 74 90 01 01 00 00 01 72 3e 03 00 70 72 42 03 00 70 6f 90 01 01 00 00 0a 17 8d 90 01 01 00 00 01 25 16 1f 2d 9d 90 00 } //01 00 
		$a_01_1 = {41 00 46 00 2e 00 79 00 32 00 } //00 00  AF.y2
	condition:
		any of ($a_*)
 
}