
rule Trojan_BAT_AgentTesla_ABIL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABIL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {0c 06 08 6f 90 01 03 0a 00 06 18 6f 90 01 03 0a 00 06 6f 90 01 03 0a 02 16 02 8e 69 6f 90 01 03 0a 0d 09 13 04 2b 00 11 04 2a 90 00 } //4
		$a_01_1 = {52 00 49 00 64 00 6a 00 46 00 61 00 64 00 77 00 76 00 72 00 64 00 45 00 71 00 77 00 44 00 59 00 65 00 61 00 54 00 6a 00 4b 00 73 00 4f 00 59 00 69 00 59 00 41 00 49 00 73 00 4e 00 77 00 47 00 4c 00 58 00 6f 00 } //1 RIdjFadwvrdEqwDYeaTjKsOYiYAIsNwGLXo
		$a_01_2 = {54 00 65 00 74 00 72 00 69 00 73 00 50 00 72 00 6f 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 TetrisPro.Properties.Resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}