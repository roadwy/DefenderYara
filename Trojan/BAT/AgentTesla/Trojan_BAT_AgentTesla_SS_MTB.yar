
rule Trojan_BAT_AgentTesla_SS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 05 09 11 05 09 8e 69 5d 91 06 11 05 91 61 d2 9c 11 05 17 58 13 05 11 05 06 8e 69 32 e0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_SS_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 5d 13 05 06 17 58 08 5d 13 0a 07 11 0a 91 20 00 01 00 00 58 13 0b 07 11 05 91 13 0c 07 11 05 11 0c 11 06 06 1f 16 5d 91 61 11 0b 59 20 00 01 00 00 5d d2 9c 06 17 58 0a 06 08 11 07 17 58 5a fe 04 13 0d 11 0d 2d b7 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}