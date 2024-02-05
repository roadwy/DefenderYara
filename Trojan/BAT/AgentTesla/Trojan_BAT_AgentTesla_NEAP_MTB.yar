
rule Trojan_BAT_AgentTesla_NEAP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {38 00 00 00 00 11 00 6f 90 01 01 00 00 0a 11 03 16 11 03 8e 69 6f 90 01 01 00 00 0a 13 04 38 41 00 00 00 11 00 18 90 00 } //02 00 
		$a_01_1 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //02 00 
		$a_01_2 = {59 00 74 00 61 00 61 00 61 00 6a 00 63 00 65 00 72 00 7a 00 67 00 75 00 69 00 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}