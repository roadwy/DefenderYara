
rule Trojan_BAT_AgentTesla_RSH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RSH!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {04 06 72 cb 11 00 70 6f 2f 00 00 0a 74 2c 00 00 01 72 d3 11 00 70 72 d7 11 00 70 6f 30 00 00 0a 17 8d 33 00 00 01 25 16 1f 2d 9d 6f 31 00 00 0a 0b 07 8e 69 8d 34 00 00 01 0c 16 13 06 2b 18 } //1
		$a_01_1 = {18 00 08 11 06 07 11 06 9a 1f 10 28 32 00 00 0a d2 9c 00 11 06 17 58 13 06 11 06 07 8e 69 fe 04 13 07 11 07 2d db } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}