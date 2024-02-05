
rule Trojan_BAT_AgentTesla_DZO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DZO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3e e0 81 3f 7a e0 63 1e d0 c6 f7 75 e0 8b 0c dc 97 39 f0 0d 0e 7c c3 03 df fa c0 c7 38 f0 2d 0e 7c ab 03 df fc c0 d7 7f 7a ff 9a 07 be e9 01 f9 } //01 00 
		$a_01_1 = {e9 1d 8e af 08 a7 1c d8 7d e3 4c cf 3a 97 1f 33 9f e3 e7 de fe 2d fb af 3d ee f0 ca 73 06 c5 16 d3 8b a7 ba f6 70 ac 7d d3 8b f6 9b 2b c8 cf b6 } //01 00 
		$a_01_2 = {1b df bf 6e 3a 60 e6 ef 36 9a e7 d1 91 26 07 08 df 93 9c b3 cf e0 b4 d7 bb d8 70 f6 59 74 f1 f3 9d b6 7a f7 e2 4a b4 d3 2f e8 9b 65 b6 e4 9d 1e } //00 00 
	condition:
		any of ($a_*)
 
}