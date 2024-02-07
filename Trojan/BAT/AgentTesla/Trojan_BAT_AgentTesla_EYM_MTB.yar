
rule Trojan_BAT_AgentTesla_EYM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EYM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 00 57 00 44 00 52 00 45 00 4c 00 48 00 78 00 65 00 55 00 49 00 42 00 56 00 70 00 22 06 42 00 5a 00 45 00 77 00 6b 00 34 00 75 00 66 00 37 00 } //01 00  UWDRELHxeUIBVpآBZEwk4uf7
		$a_01_1 = {77 00 73 00 34 00 66 00 2f 00 2f 00 2f 00 2f 00 33 00 4d 00 47 00 41 00 22 06 4b 00 43 00 67 00 49 00 67 00 70 00 67 00 49 00 22 06 43 00 44 00 } //00 00  ws4f////3MGAآKCgIgpgIآCD
	condition:
		any of ($a_*)
 
}