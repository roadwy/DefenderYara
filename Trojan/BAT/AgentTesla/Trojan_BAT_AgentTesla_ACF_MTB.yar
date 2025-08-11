
rule Trojan_BAT_AgentTesla_ACF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ACF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {26 02 11 12 11 13 6f ?? 00 00 0a 13 15 12 15 28 ?? 00 00 0a 16 61 d2 13 16 12 15 28 ?? 00 00 0a 16 61 d2 13 17 12 15 28 ?? 00 00 0a 16 61 d2 13 18 19 8d ?? 00 00 01 25 16 11 16 6c } //4
		$a_03_1 = {16 61 13 13 12 12 28 ?? 00 00 0a 72 ?? ?? 00 70 12 13 28 ?? 00 00 0a 28 3d 00 00 0a 11 0b } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}