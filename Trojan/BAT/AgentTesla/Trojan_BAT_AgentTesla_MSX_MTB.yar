
rule Trojan_BAT_AgentTesla_MSX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MSX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {20 00 01 00 00 14 14 90 01 01 8d 90 01 02 00 01 25 16 90 01 01 a2 25 90 01 02 8d 90 01 02 00 01 25 16 7e 90 01 02 00 04 a2 25 17 7e 90 01 02 00 04 a2 25 18 72 90 01 02 00 70 a2 90 01 01 6f 90 01 02 00 0a 26 90 00 } //01 00 
		$a_80_1 = {4c 69 62 72 61 72 79 4d 61 6e 61 67 65 6d 65 6e 74 53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //LibraryManagementSystem.Resources.resources  01 00 
		$a_80_2 = {53 74 75 64 69 6f 62 6f 72 6e 65 2e 52 65 73 6f 75 72 63 65 73 } //Studioborne.Resources  00 00 
	condition:
		any of ($a_*)
 
}