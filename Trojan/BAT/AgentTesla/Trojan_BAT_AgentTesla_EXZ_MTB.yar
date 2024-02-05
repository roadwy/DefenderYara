
rule Trojan_BAT_AgentTesla_EXZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {07 06 20 00 b4 00 00 5d 07 06 20 00 b4 00 00 5d 91 09 06 1f 16 5d 6f 90 01 03 0a 61 28 90 01 03 0a 07 06 17 58 20 00 b4 00 00 5d 91 28 90 01 03 0a 59 20 00 01 00 00 58 d2 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_EXZ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {15 d1 1c 2b b8 62 e5 82 08 b2 26 07 31 b3 c6 ca 29 dd ca 6e a0 df bc 1c 5a c8 23 6b c5 7c 77 b2 db 43 76 74 71 5a 75 bd 3d e9 0c 77 8d 4e 9a 62 } //01 00 
		$a_01_1 = {f9 45 7b a2 84 fe 89 3a bd 4c 29 5e 67 b2 70 dd 4f 90 8c a8 9c ab 3b 63 f1 55 96 32 89 ac 29 5a 17 8f ba ce a3 06 f1 18 7e 1f bf 9b 13 d1 2e ed } //01 00 
		$a_01_2 = {db 43 76 74 71 5a 75 bd 3d e9 0c 77 8d 4e 9a 62 94 4d e1 65 85 c2 19 82 b6 a5 ae 2d 46 d3 fc 46 db 43 76 74 71 5a 75 bd 3d e9 0c 77 8d 4e 9a 62 } //00 00 
	condition:
		any of ($a_*)
 
}