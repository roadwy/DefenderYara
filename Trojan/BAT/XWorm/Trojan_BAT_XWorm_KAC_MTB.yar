
rule Trojan_BAT_XWorm_KAC_MTB{
	meta:
		description = "Trojan:BAT/XWorm.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 03 00 00 2b 0b 2b 00 07 2a } //01 00 
		$a_01_1 = {34 00 35 00 34 00 37 00 39 00 37 00 30 00 36 00 35 00 30 00 30 00 35 00 30 00 37 00 32 00 36 } //00 00 
	condition:
		any of ($a_*)
 
}