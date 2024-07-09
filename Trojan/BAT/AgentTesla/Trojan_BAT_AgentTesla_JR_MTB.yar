
rule Trojan_BAT_AgentTesla_JR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 08 18 6f ?? 00 00 0a 20 03 02 00 00 28 ?? 00 00 0a 13 07 09 11 07 8c ?? 00 00 01 6f 63 00 00 0a 26 08 18 58 0c 08 07 6f } //2
		$a_03_1 = {00 00 0a 13 05 11 05 6f ?? 00 00 0a 16 9a } //2
		$a_01_2 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}