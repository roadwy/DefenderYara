
rule Trojan_BAT_Zusy_GPC_MTB{
	meta:
		description = "Trojan:BAT/Zusy.GPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {7e 03 00 00 04 6f 90 01 01 00 00 0a 02 0e 04 03 8e 69 6f 90 01 01 00 00 0a 0a 06 0b 2b 00 07 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}