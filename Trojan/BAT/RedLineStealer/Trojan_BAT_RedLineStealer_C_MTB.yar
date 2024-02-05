
rule Trojan_BAT_RedLineStealer_C_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 00 06 0a 06 28 90 01 01 00 00 0a 7d 90 01 01 00 00 04 06 02 7d 90 01 01 00 00 04 06 15 7d 90 01 01 00 00 04 06 7c 90 01 01 00 00 04 12 00 28 90 01 01 00 00 2b 06 7c 90 00 } //02 00 
		$a_01_1 = {03 04 61 2a } //02 00 
		$a_01_2 = {03 04 5d 2a } //00 00 
	condition:
		any of ($a_*)
 
}