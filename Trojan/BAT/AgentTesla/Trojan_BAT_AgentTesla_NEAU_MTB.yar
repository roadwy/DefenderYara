
rule Trojan_BAT_AgentTesla_NEAU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {28 20 00 00 0a 0a 00 06 7e 0e 00 00 04 28 21 00 00 0a 6f 90 01 01 00 00 0a 00 06 18 6f 90 01 01 00 00 0a 00 06 18 6f 90 01 01 00 00 0a 00 73 65 00 00 06 0b 07 06 6f 90 01 01 00 00 0a 90 00 } //05 00 
		$a_01_1 = {41 6e 69 6d 65 4f 76 65 72 76 69 65 77 65 72 2d 6d 61 73 74 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}