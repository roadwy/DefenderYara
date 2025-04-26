
rule Trojan_BAT_AgentTesla_AEG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {07 ff c4 06 f7 d1 84 ff a6 ae ff a6 05 9f 7f c1 cf 7e 3a 87 fb a9 0b 3e fb 82 4f 5a f0 77 2f 60 e3 5f b1 e0 5f 18 b8 af b5 e0 9b 2d f8 77 16 7c } //1
		$a_01_1 = {0c d3 2f 0d fa b4 63 b7 7b 9e 83 b8 a2 d3 6f d5 cb 73 10 ee 1b 93 e7 b9 ce a6 01 4d 97 e7 20 3c a7 8f ae bf c1 12 68 ba 3c 07 61 ff 14 5d de 3b } //1
		$a_01_2 = {75 b2 63 c0 be b5 63 ee a5 47 ff ce 1f 69 87 d6 b7 e3 2b 76 de db 6f d2 5f 52 2f 79 2a f5 52 de 72 e3 9f 96 1b bc 7b ae b3 fc 2a 8e 1e ed 37 d1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}