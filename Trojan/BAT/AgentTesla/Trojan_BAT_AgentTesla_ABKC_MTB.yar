
rule Trojan_BAT_AgentTesla_ABKC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 08 17 8d ?? ?? ?? 01 25 16 11 04 8c ?? ?? ?? 01 a2 14 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 11 04 } //5
		$a_01_1 = {70 00 6f 00 6e 00 67 00 72 00 6f 00 6f 00 74 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 pongroot.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}