
rule Trojan_BAT_AgentTesla_ABIY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABIY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 06 07 06 9a 1f 10 28 90 01 03 0a 9c 06 17 d6 0a 06 07 8e 69 fe 04 13 08 11 08 2d e3 90 00 } //01 00 
		$a_01_1 = {54 61 62 43 6f 6e 74 72 6f 6c 45 78 74 72 61 2e 58 4c 4c 4c 2e 72 65 73 6f 75 72 63 65 73 } //00 00  TabControlExtra.XLLL.resources
	condition:
		any of ($a_*)
 
}