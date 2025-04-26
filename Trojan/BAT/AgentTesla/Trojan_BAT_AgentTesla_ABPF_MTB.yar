
rule Trojan_BAT_AgentTesla_ABPF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 11 04 8c ?? ?? ?? 01 a2 14 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 06 09 11 06 28 ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 11 04 17 d6 13 04 00 11 04 20 ?? ?? ?? 00 fe 04 13 07 11 07 2d b7 90 0a 49 00 08 17 8d } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}