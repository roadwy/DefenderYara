
rule Trojan_BAT_AgentTesla_GN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0a 06 14 19 8d ?? ?? ?? 01 25 16 7e ?? ?? ?? 04 a2 25 17 7e ?? ?? ?? ?? a2 25 18 72 ?? ?? ?? 70 a2 14 6f ?? ?? ?? 0a [0-10] 2a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_GN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {06 08 06 8e 69 6a 5d d4 06 08 06 8e 69 6a 5d d4 91 07 08 07 8e 69 6a 5d d4 91 61 28 ?? ?? ?? 0a 06 08 17 6a 58 06 8e 69 6a 5d d4 91 28 ?? ?? ?? 0a 59 20 ?? ?? ?? 00 58 20 ?? ?? ?? 00 5d 28 ?? ?? ?? 0a 9c 00 08 17 6a 58 0c 08 06 8e 69 17 59 6a 02 17 58 6e 5a fe 02 16 fe 01 0d 09 2d a0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}