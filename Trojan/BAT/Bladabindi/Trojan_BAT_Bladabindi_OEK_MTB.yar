
rule Trojan_BAT_Bladabindi_OEK_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.OEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b 07 06 1f 10 6f 90 01 03 0a 6f 90 01 03 0a 00 07 06 1f 10 6f 90 01 03 0a 6f 90 01 03 0a 00 07 6f 90 01 03 0a 02 16 02 8e 69 6f 90 01 03 0a 0c 08 8e 69 1f 10 59 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}