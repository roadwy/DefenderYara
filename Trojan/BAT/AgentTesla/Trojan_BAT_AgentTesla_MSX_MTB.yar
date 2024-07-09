
rule Trojan_BAT_AgentTesla_MSX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MSX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_02_0 = {20 00 01 00 00 14 14 ?? 8d ?? ?? 00 01 25 16 ?? a2 25 ?? ?? 8d ?? ?? 00 01 25 16 7e ?? ?? 00 04 a2 25 17 7e ?? ?? 00 04 a2 25 18 72 ?? ?? 00 70 a2 ?? 6f ?? ?? 00 0a 26 } //10
		$a_80_1 = {4c 69 62 72 61 72 79 4d 61 6e 61 67 65 6d 65 6e 74 53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //LibraryManagementSystem.Resources.resources  1
		$a_80_2 = {53 74 75 64 69 6f 62 6f 72 6e 65 2e 52 65 73 6f 75 72 63 65 73 } //Studioborne.Resources  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=11
 
}