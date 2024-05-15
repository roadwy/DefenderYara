
rule Trojan_BAT_AgentTesla_SGB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {7e 02 00 00 04 7e 03 00 00 04 28 0f 00 00 0a 28 06 00 00 0a 26 2a } //01 00 
		$a_00_1 = {4c 00 6f 00 6f 00 74 00 41 00 6c 00 65 00 72 00 74 00 2e 00 65 00 78 00 65 00 } //00 00  LootAlert.exe
	condition:
		any of ($a_*)
 
}