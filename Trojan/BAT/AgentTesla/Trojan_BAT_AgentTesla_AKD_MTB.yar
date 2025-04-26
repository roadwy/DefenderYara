
rule Trojan_BAT_AgentTesla_AKD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 11 06 02 11 06 91 08 61 07 11 07 91 61 b4 9c 20 00 00 00 00 38 ?? ?? ?? ?? ?? 28 ?? ?? ?? 06 03 } //10
		$a_03_1 = {02 02 8e 69 17 da 91 1f 70 61 0c 02 8e 69 17 d6 17 da 17 d6 8d ?? ?? ?? 01 0d } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}