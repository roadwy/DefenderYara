
rule Trojan_BAT_AgentTesla_NGA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 2b 4b 00 08 14 72 ?? ?? ?? 70 18 8d ?? ?? ?? 01 25 16 09 8c ?? ?? ?? 01 a2 25 17 11 04 8c ?? ?? ?? 01 a2 14 14 28 ?? ?? ?? 0a a5 ?? ?? ?? 01 13 05 11 05 28 ?? ?? ?? 0a 13 06 02 07 09 11 06 d2 28 ?? ?? ?? 06 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 07 11 07 2d aa 06 17 58 0a 00 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}