
rule Trojan_BAT_AgentTesla_NPM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0b 00 07 28 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 6f 90 01 03 0a 0c 06 08 6f 90 01 03 0a 00 06 18 6f 90 01 03 0a 00 02 0d 06 6f 90 01 03 0a 09 16 09 8e 69 6f 90 01 03 0a 13 04 de 16 90 00 } //01 00 
		$a_80_1 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 39 35 } //cdn.discordapp.com/attachments/95  01 00 
		$a_01_2 = {28 02 00 00 06 0a 06 1f 09 18 28 05 00 00 06 0a 06 1d 19 28 05 00 00 06 } //01 00 
		$a_01_3 = {47 65 74 54 79 70 65 } //01 00 
		$a_01_4 = {6e 65 77 4e 6f 64 65 } //01 00 
		$a_01_5 = {47 65 74 4d 65 74 68 6f 64 } //01 00 
		$a_01_6 = {54 6f 42 75 66 66 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}