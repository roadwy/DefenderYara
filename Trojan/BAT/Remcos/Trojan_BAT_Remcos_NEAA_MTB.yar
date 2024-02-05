
rule Trojan_BAT_Remcos_NEAA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {2b 05 2b 0a 2b 0f 2a 28 90 01 01 00 00 0a 2b f4 28 90 01 01 00 00 06 2b ef 6f 90 01 01 00 00 0a 2b ea 90 00 } //05 00 
		$a_03_1 = {2b 0a 2b 0b 18 2b 0b 1f 10 2b 0e 2a 02 2b f3 03 2b f2 6f 90 01 01 00 00 0a 2b ee 28 90 01 01 00 00 0a 2b eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}