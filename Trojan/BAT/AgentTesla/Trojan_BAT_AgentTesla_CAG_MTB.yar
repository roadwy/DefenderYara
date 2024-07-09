
rule Trojan_BAT_AgentTesla_CAG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 3b 09 17 8d ?? 00 00 01 25 16 08 17 8d ?? 00 00 01 25 16 11 04 8c ?? 00 00 01 a2 14 28 ?? ?? ?? 0a 28 ?? 00 00 0a 1f 10 28 ?? ?? ?? 0a b4 9c 6f ?? ?? ?? 0a 00 11 04 17 d6 13 04 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_AgentTesla_CAG_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CAG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 06 02 11 06 91 08 61 07 11 07 91 61 b4 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}