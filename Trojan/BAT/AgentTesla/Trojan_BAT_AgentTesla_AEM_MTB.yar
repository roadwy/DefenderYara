
rule Trojan_BAT_AgentTesla_AEM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {25 16 19 8d ?? ?? ?? 01 25 16 7e ?? ?? ?? 04 a2 25 17 7e ?? ?? ?? 04 a2 25 18 72 ?? ?? ?? 70 a2 a2 6f ?? ?? ?? 0a 26 20 00 08 00 00 0a } //10
		$a_02_1 = {09 11 04 9a 13 05 11 05 28 ?? ?? ?? 0a 23 00 00 00 00 00 80 73 40 59 28 ?? ?? ?? 0a b7 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}