
rule Trojan_BAT_Remcos_AMMB_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AMMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 05 0e 07 0e 04 8e 69 6f 90 01 01 00 00 0a 0a 06 0b 2b 00 07 2a 90 00 } //02 00 
		$a_03_1 = {0a 00 02 03 02 03 02 02 03 05 28 90 01 01 00 00 06 0a 2b 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}