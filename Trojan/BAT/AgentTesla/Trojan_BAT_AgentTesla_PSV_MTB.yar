
rule Trojan_BAT_AgentTesla_PSV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 00 7e 07 00 00 04 11 01 7e 07 00 00 04 8e 69 5d 91 02 11 01 91 61 d2 6f 15 90 01 03 38 43 90 01 03 11 00 6f 16 90 01 03 25 3a 4a 90 01 03 26 38 43 90 01 03 73 17 90 01 03 13 00 38 2f 90 01 03 38 ba 90 01 03 20 90 01 03 00 7e 35 00 00 04 7b 30 00 00 04 39 7f 90 01 03 26 20 90 01 03 00 38 74 90 01 03 11 01 17 58 13 01 38 77 90 01 03 16 13 01 38 7e 90 01 03 14 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}