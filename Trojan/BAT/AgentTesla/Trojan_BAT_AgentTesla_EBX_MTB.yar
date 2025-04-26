
rule Trojan_BAT_AgentTesla_EBX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {da f8 c1 0e 7c f9 81 fb ea 07 be f5 81 6f 73 e0 bb 1d f8 c4 07 be f3 81 ef 7a e0 3b 1d f8 56 4f cf df e4 c0 77 38 a0 fc 9b 3d e5 bf e3 13 a0 fb } //1
		$a_01_1 = {a5 d7 7e af 5f 1d 7c c9 da 86 ff e7 a7 62 d9 c4 a9 d7 1a c5 bc a8 7e f5 90 5b 3c e7 bf d5 45 1f f5 cf 71 a8 7e f6 d4 d7 f7 78 a6 1f d4 8e 7d 36 } //1
		$a_01_2 = {c7 1a 27 c5 ab 6d 9f e4 e4 df 7b 5c bf ae 78 d5 7e 38 7f 2b 5f 1a 9d 73 19 69 ed 98 e7 33 a0 ff f7 d4 79 f6 4b ed 73 6b 5e df 71 33 7f ac 3c fa } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}