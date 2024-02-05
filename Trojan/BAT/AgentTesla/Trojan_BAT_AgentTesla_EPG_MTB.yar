
rule Trojan_BAT_AgentTesla_EPG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {97 64 71 96 c1 f9 70 1c 18 b8 6c a8 ba 47 ca 70 b4 e2 34 95 8b a4 c7 a3 e6 8d d3 22 15 59 4f 45 da 4b be fe c2 55 49 2c 34 70 8d e9 e2 58 7c fe } //01 00 
		$a_01_1 = {83 85 fa 6f de 82 a3 4a 72 55 bc ed e2 12 3a bb c9 14 81 fe b8 d1 cf 0a 7f eb c7 fb c6 84 b8 3f 00 e5 1c 1f 94 47 f6 57 5e e7 7c ea c7 3e c1 f3 } //01 00 
		$a_01_2 = {3a cf 24 ba e7 9c 74 50 4e e1 f9 fc d7 ee 63 05 6e 00 7f ca 99 fb 1e 51 b5 92 ed e2 87 1d 41 ac d0 90 26 a2 3c 37 73 68 ae e6 f0 85 73 19 1a 23 } //00 00 
	condition:
		any of ($a_*)
 
}