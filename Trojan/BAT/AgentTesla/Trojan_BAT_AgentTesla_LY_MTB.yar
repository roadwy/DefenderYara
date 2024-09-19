
rule Trojan_BAT_AgentTesla_LY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {06 0b 07 06 8e 69 1f 40 12 02 28 } //2
		$a_01_1 = {09 11 04 58 06 11 04 91 52 } //2
		$a_01_2 = {11 04 17 58 13 04 11 04 06 8e 69 fe 04 13 05 11 05 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}