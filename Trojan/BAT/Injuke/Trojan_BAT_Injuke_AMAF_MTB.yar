
rule Trojan_BAT_Injuke_AMAF_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AMAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 11 04 73 90 01 01 00 00 0a 09 07 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 28 90 01 01 00 00 06 28 90 01 01 00 00 2b 16 fe 01 13 90 00 } //01 00 
		$a_03_1 = {02 1f 10 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 0b 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}