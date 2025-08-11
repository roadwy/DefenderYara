
rule Trojan_BAT_AgentTesla_MBW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 17 58 0a 11 ?? 17 58 13 } //1
		$a_01_1 = {6f 00 61 00 64 00 00 05 74 00 6e 00 00 03 4c } //3
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 } //1 InvokeMembe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1) >=5
 
}