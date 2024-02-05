
rule Trojan_BAT_AgentTesla_NTT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {20 ee db d0 24 25 26 fe 90 01 02 00 20 90 01 03 38 5b 61 38 90 01 03 ff 00 fe 90 01 02 00 fe 90 01 02 00 20 90 01 03 00 8d 90 01 03 01 fe 90 01 02 00 fe 90 01 02 00 20 90 01 03 00 90 00 } //01 00 
		$a_01_1 = {52 61 79 58 2e 50 72 6f 70 65 72 74 69 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NTT_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 0a 03 02 20 00 14 01 00 04 28 90 01 01 00 00 06 03 04 17 58 20 00 14 01 00 5d 91 59 06 58 06 5d 0b 03 04 20 00 14 01 00 5d 07 d2 9c 03 0c 2b 00 90 00 } //01 00 
		$a_03_1 = {02 05 04 5d 91 03 05 1f 16 5d 6f 90 01 03 0a 61 0a 2b 00 06 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}