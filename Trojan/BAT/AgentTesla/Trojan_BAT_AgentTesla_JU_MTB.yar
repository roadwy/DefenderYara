
rule Trojan_BAT_AgentTesla_JU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {09 08 11 05 18 6f 90 01 01 00 00 0a 1f 10 28 90 00 } //2
		$a_01_1 = {11 05 18 58 13 05 11 05 08 6f } //2 ԑ堘ԓԑ漈
		$a_01_2 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}