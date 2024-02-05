
rule Trojan_BAT_AgentTesla_ECH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ECH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {14 74 fd 7d c6 f9 15 fc 75 17 b8 2f 4c f8 4f d6 f5 1f 74 e0 4f 38 f0 3f bd 3b 87 fb 1e 07 7e df 03 3f fe c0 9f 74 80 8d bf db 81 bf 73 e0 fe 81 } //01 00 
		$a_01_1 = {ac c3 5c 3b f6 bd 4e 6d d6 1b ce bd 07 e2 da 73 46 d7 ee 1f ac c5 bd d7 03 ef dc d1 fc 97 0c 7d 98 8f d1 aa b3 de 55 c1 4b e6 95 2c df 06 c0 5b } //01 00 
		$a_01_2 = {97 e8 aa 53 d1 d5 be fb cd 3f bb df f0 9e 85 cf f6 e7 f2 e8 b5 e3 26 3d f2 6b e3 32 3d 3a 6e 68 3d d3 7b 4f f9 bb ff a9 92 fc fa db f6 ed 3a d6 } //00 00 
	condition:
		any of ($a_*)
 
}