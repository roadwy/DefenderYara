
rule Trojan_BAT_AgentTesla_SR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 50 08 03 50 8e 69 6a 5d b7 03 50 08 03 50 8e 69 6a 5d b7 91 06 08 06 8e 69 6a 5d b7 91 61 03 50 08 17 6a d6 03 50 8e 69 6a 5d b7 91 da 20 ?? ?? ?? ?? d6 20 ?? ?? ?? ?? 5d b4 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_BAT_AgentTesla_SR_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 22 11 04 5d 13 23 11 22 17 58 11 04 5d 13 24 07 11 24 91 20 00 01 00 00 58 13 25 07 11 23 91 13 26 11 26 08 11 22 1f 16 5d 91 61 13 27 11 27 11 25 59 13 28 07 11 23 11 28 20 00 01 00 00 5d d2 9c 00 11 22 17 58 13 22 11 22 11 04 09 17 58 5a fe 04 13 29 11 29 2d a6 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}