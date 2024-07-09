
rule Trojan_BAT_AgentTesla_NUN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NUN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 11 08 17 da 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 11 04 11 08 11 04 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 da 13 09 11 05 11 09 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 05 11 08 17 d6 13 08 11 08 11 07 31 b7 } //1
		$a_01_1 = {49 00 6e 00 00 05 76 00 6f 00 00 05 6b 00 65 00 00 0f 53 00 74 00 72 00 69 00 6e 00 67 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}