
rule Trojan_BAT_Chopper_SPD_MTB{
	meta:
		description = "Trojan:BAT/Chopper.SPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {0a 0a 02 6f 12 00 00 0a 28 90 01 03 0a 74 90 01 03 01 7b 90 01 03 0a 25 16 03 a2 25 17 04 a2 25 18 06 a2 26 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}