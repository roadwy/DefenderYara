
rule Trojan_BAT_AgentTesla_BSV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BSV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {11 07 11 01 02 11 01 91 11 03 61 d2 9c } //1
		$a_02_1 = {11 02 11 06 11 00 94 58 13 02 38 90 01 04 11 00 20 00 01 00 00 5d 13 00 20 01 00 00 00 90 00 } //1
		$a_00_2 = {11 06 11 06 11 00 94 11 06 11 02 94 58 20 00 01 00 00 5d 94 13 03 20 02 00 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}