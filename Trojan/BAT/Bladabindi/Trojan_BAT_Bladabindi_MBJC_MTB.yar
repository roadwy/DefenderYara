
rule Trojan_BAT_Bladabindi_MBJC_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.MBJC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 72 ff 01 00 70 16 14 28 90 01 01 00 00 0a 26 00 2a 90 00 } //01 00 
		$a_01_1 = {39 62 2d 32 37 30 61 65 33 32 37 61 31 32 } //00 00  9b-270ae327a12
	condition:
		any of ($a_*)
 
}