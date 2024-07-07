
rule Trojan_BAT_AgentTesla_DYQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DYQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {17 fc 5c 17 fc eb 17 fc 32 17 e8 e3 cf 72 c1 ef 52 79 bf d7 05 7f f4 05 7f cc 05 7f ea 05 bf f4 05 7f d2 05 7f ca 05 7f e2 05 7f d4 db ef 3f e4 } //1
		$a_01_1 = {96 df ef 1e 24 3f 7d b5 ce 4b 99 f6 dc cb 65 5b 80 9c fa 0e 2c 5c 31 10 1f c2 cf ed 5e 30 3f 17 ff 82 cf 5e b7 47 fe 79 a7 ca dd 6d df ec f5 bb } //1
		$a_01_2 = {5a ab e7 ae 2a ff ea 0c 36 f7 d5 9c fb f2 55 af ee 62 a1 e5 1c 1d 0d 79 ee 28 39 a7 0d ff 69 b3 c1 5c 9d 7c f2 a3 e3 ee 3b 9b 53 f6 19 1c df 77 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}