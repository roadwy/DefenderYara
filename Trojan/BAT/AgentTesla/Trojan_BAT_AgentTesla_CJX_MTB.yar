
rule Trojan_BAT_AgentTesla_CJX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 01 02 11 03 18 28 ?? ?? ?? 06 1f 10 28 ?? ?? ?? 06 84 } //1
		$a_01_1 = {02 02 8e 69 17 da 91 1f 70 61 13 02 } //1
		$a_01_2 = {11 03 11 06 11 08 11 02 61 11 09 61 b4 9c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}