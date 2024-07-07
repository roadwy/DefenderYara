
rule Trojan_BAT_AgentTesla_EOH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EOH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c cb 4f 20 2f 69 5d e7 4b 67 5a 2f cf 42 43 44 c0 38 42 43 c8 df 40 2b 4b 20 2f 59 bd d7 4b e7 1a 8d c3 42 43 46 cc 38 42 43 cd d1 81 34 f1 ab } //1
		$a_01_1 = {cd dd a4 1d 7c 19 40 2d 1e ba 6a 42 6a 38 c9 bd 87 a9 32 73 ec d6 20 03 b3 95 ea d9 e8 2d 7d b8 9b ba b2 38 b0 4b d9 a3 58 57 0f d0 44 60 99 a7 } //1
		$a_01_2 = {2f 59 bd d7 4b 47 5a 2d c3 40 47 44 cc 38 42 43 c8 df 4c 2b 4f 20 2f 59 bd d7 4b 47 5a 2d c3 40 47 44 cc 38 42 43 c8 df 4c 2b 4f 20 2f 59 bd d7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}