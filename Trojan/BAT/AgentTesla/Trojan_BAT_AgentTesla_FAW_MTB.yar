
rule Trojan_BAT_AgentTesla_FAW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 08 11 06 6f 90 01 01 00 00 0a d4 8d 90 01 01 00 00 01 13 09 11 06 16 6a 6f 90 01 01 00 00 0a 11 06 11 09 16 11 09 8e 69 6f 90 01 01 00 00 0a 26 11 09 28 90 01 01 00 00 0a 13 0a 11 0a 2a 90 00 } //3
		$a_03_1 = {0c 08 07 07 6f 90 01 01 00 00 0a 0d 17 13 04 72 01 00 00 70 13 05 11 05 90 00 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}