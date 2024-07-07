
rule Trojan_BAT_AgentTesla_EPH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {ed 75 79 e7 93 88 90 fd 10 e4 5f a2 b0 d9 46 e2 a5 9d ca ce 52 62 e6 a4 d7 24 9d 2e 07 38 d3 18 66 eb 72 4e 34 9d ca e8 dc 2b 05 8e d7 23 bd 84 } //1
		$a_01_1 = {7f f1 5d d4 76 3c 1d 01 dc 25 76 85 ed 2c fa e6 39 62 19 fa de 77 33 3f 7a 14 f5 a3 69 a8 54 36 fe 66 82 59 ec fe 55 be 9f 78 ac 78 dd bf 0f 2e } //1
		$a_01_2 = {45 81 09 fa b5 5c a5 e4 26 1d 6c bd 00 80 83 a6 c2 49 69 42 9c 9b 2f 50 cf 7b 5d f0 fc 37 8c 31 73 59 a8 e5 9f 0d 36 65 24 75 65 d8 81 ed b6 dd } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}