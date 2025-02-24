
rule Trojan_BAT_AgentTesla_RSH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {57 17 a2 1f 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 a1 00 00 00 22 00 00 00 71 00 00 00 aa 00 00 00 9f 00 00 00 05 00 00 00 42 01 00 00 69 00 00 00 30 00 00 00 08 00 00 00 14 00 00 00 1b 00 00 00 07 00 00 00 02 00 00 00 2b 00 00 00 08 00 00 00 01 00 00 00 09 00 00 00 03 00 00 00 10 00 00 00 07 00 00 00 14 } //1
		$a_81_1 = {32 66 62 33 63 64 31 63 2d 30 63 38 61 2d 34 33 65 61 2d 62 65 35 39 2d 37 61 39 37 38 39 65 65 65 36 35 63 } //1 2fb3cd1c-0c8a-43ea-be59-7a9789eee65c
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_RSH_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RSH!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {04 06 72 cb 11 00 70 6f 2f 00 00 0a 74 2c 00 00 01 72 d3 11 00 70 72 d7 11 00 70 6f 30 00 00 0a 17 8d 33 00 00 01 25 16 1f 2d 9d 6f 31 00 00 0a 0b 07 8e 69 8d 34 00 00 01 0c 16 13 06 2b 18 } //1
		$a_01_1 = {18 00 08 11 06 07 11 06 9a 1f 10 28 32 00 00 0a d2 9c 00 11 06 17 58 13 06 11 06 07 8e 69 fe 04 13 07 11 07 2d db } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}