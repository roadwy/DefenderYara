
rule Trojan_BAT_AgentTesla_ENH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ENH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {ba 21 3d de cc 4b 9c e1 64 17 de 58 bb f0 d4 3b 4f 9d d6 29 14 44 02 1b 3d fe cc 49 3e 40 93 e4 db b8 bb d0 d4 db 44 bd d1 29 d4 c4 42 3b 3d 7e } //01 00 
		$a_01_1 = {f5 00 fb cd a7 53 7b 79 0e ee ae 69 93 5a 33 15 79 5c cd 68 ea 90 c6 8a de 0a 68 40 6b 67 da c9 b2 c6 c1 e9 86 f9 c5 73 b2 8b 09 74 47 05 cc 8a } //01 00 
		$a_01_2 = {40 bd d5 29 d4 c4 42 3b 3d de cc 4b 3e 4e 97 e4 df b8 bb d0 d4 db 40 bd d5 29 d4 c4 42 3b 3d de cc 4b 3e 4e 97 e4 df b8 bb d0 d4 db 40 bd d5 29 } //00 00 
	condition:
		any of ($a_*)
 
}