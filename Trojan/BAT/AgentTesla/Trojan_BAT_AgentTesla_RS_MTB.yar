
rule Trojan_BAT_AgentTesla_RS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RS!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 94 58 20 00 01 00 00 5d 94 13 07 09 11 05 08 11 05 91 11 07 61 d2 9c 11 05 17 58 13 05 11 05 08 8e 69 32 95 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_BAT_AgentTesla_RS_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 09 28 55 00 00 06 28 53 00 00 06 28 52 00 00 06 28 54 00 00 06 28 51 00 00 06 28 50 00 00 06 d2 06 28 4e 00 00 06 09 17 58 0d 09 17 fe 04 13 04 11 04 2d ca } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_RS_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RS!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 28 13 00 00 0a 72 01 00 00 70 6f 14 00 00 0a 08 28 13 00 00 0a 72 01 00 00 70 6f 14 00 00 0a 8e 69 5d 91 06 08 91 61 d2 6f 15 00 00 0a 08 17 58 0c 08 06 8e 69 32 c8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_BAT_AgentTesla_RS_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.RS!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {6f a4 00 00 0a 72 73 0c 00 70 72 77 0c 00 70 } //5
		$a_01_1 = {07 06 11 07 9a 1f 10 28 a7 00 00 0a 6f a8 00 00 0a 00 11 07 17 58 13 07 11 07 20 00 ea 00 00 fe 04 13 08 11 08 2d d9 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}
rule Trojan_BAT_AgentTesla_RS_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.RS!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 12 06 28 1a 00 00 0a 08 06 18 6f 1b 00 00 0a 11 04 28 1c 00 00 0a 13 07 07 06 11 07 6f 1d 00 00 0a de 0b } //1
		$a_01_1 = {07 6f 20 00 00 0a 28 01 00 00 2b 13 05 1c 2c a5 11 05 2a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_RS_MTB_6{
	meta:
		description = "Trojan:BAT/AgentTesla.RS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 08 09 11 04 28 8c 00 00 06 28 8a 00 00 06 00 28 89 00 00 06 28 8b 00 00 06 28 88 00 00 06 00 07 17 8d 58 00 00 01 25 16 28 87 00 00 06 d2 9c 6f 59 00 00 0a 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 05 11 05 2d b8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}