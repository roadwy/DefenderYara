
rule Trojan_BAT_AgentTesla_ABHL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {1b 08 18 5b 02 08 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 17 13 04 2b a4 08 18 58 0c 16 13 04 2b 9b 90 0a 27 00 07 75 90 00 } //01 00 
		$a_01_1 = {44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 41 00 70 00 70 00 31 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}