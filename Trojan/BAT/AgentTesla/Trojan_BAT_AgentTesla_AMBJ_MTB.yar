
rule Trojan_BAT_AgentTesla_AMBJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 00 0e 04 28 90 01 01 00 00 06 00 7e 90 01 01 00 00 04 6f 90 01 01 00 00 0a 05 16 03 8e 69 6f 90 01 01 00 00 0a 0a 06 0b 2b 00 07 2a 90 00 } //2
		$a_01_1 = {53 00 77 00 64 00 4c 00 66 00 6e 00 77 00 53 00 4e 00 64 00 66 00 71 00 6a 00 53 00 48 00 48 00 64 00 77 00 30 00 53 00 61 00 } //2 SwdLfnwSNdfqjSHHdw0Sa
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}