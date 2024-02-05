
rule Trojan_BAT_AgentTesla_DXN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DXN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5f 71 88 e7 94 9e 59 c6 ef 9e 3c 65 8a 3b ca 57 2e 9d 94 9b 5c b1 8d 72 f4 37 f3 12 a0 9b 3c b2 c5 67 ca 26 db b3 75 b2 3c 8f f7 5c df 3e 1c 3a } //01 00 
		$a_01_1 = {8f e0 b7 fe e2 e0 93 1c e7 75 26 fd 06 e3 cd 09 7f 9a f7 5d 17 17 da a7 96 8a 87 a5 da 26 9a 99 b6 fe 88 af b3 2a f1 19 1b a5 c6 0a 29 dd a5 f3 } //01 00 
		$a_01_2 = {b6 0f f7 df fd 01 d0 7d 9f 0b e4 7d 9b 0b be fd c3 35 be ef 7b 01 1a f7 ca e8 fa cb 5f f0 35 2f f8 ba 0f f7 64 93 f3 ed 2e c0 ff f9 2e f8 04 0f } //00 00 
	condition:
		any of ($a_*)
 
}