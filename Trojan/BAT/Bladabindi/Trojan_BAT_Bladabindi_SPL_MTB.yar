
rule Trojan_BAT_Bladabindi_SPL_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.SPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0d 1a 8d 38 00 00 01 0b 11 04 11 04 6f 90 01 03 0a 1b 6a da 6f 90 01 03 0a 11 04 07 16 1a 6f 90 01 03 0a 26 07 16 28 90 01 03 0a 0c 11 04 16 6a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}