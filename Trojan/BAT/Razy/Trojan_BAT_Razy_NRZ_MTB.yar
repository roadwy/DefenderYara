
rule Trojan_BAT_Razy_NRZ_MTB{
	meta:
		description = "Trojan:BAT/Razy.NRZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {0c 08 28 1e 00 00 0a 0a 1f 1a 28 90 01 03 0a 72 90 01 03 70 28 90 01 03 0a 0b 07 06 28 90 01 03 0a 72 90 01 03 70 72 90 01 03 70 07 72 90 01 03 70 28 90 01 03 0a 28 90 01 03 0a 90 00 } //01 00 
		$a_01_1 = {42 63 6d 63 6e 42 } //00 00 
	condition:
		any of ($a_*)
 
}