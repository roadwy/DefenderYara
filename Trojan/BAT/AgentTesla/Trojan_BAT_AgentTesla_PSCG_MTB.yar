
rule Trojan_BAT_AgentTesla_PSCG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 28 2a 00 00 06 72 97 01 00 70 72 9d 01 00 70 6f 4b ?? ?? ?? 72 a1 01 00 70 72 a5 01 00 70 6f 4b ?? ?? ?? 72 a9 01 00 70 72 ad 01 00 70 6f 4b ?? ?? ?? 72 b3 01 00 70 72 b7 01 00 70 6f 4b ?? ?? ?? 72 bb 01 00 70 72 c1 01 00 70 6f 4b ?? ?? ?? 17 8d 4f 00 00 01 25 16 1f 2d 9d 6f 4c ?? ?? ?? 0b 73 4d ?? ?? ?? 0c 16 13 08 2b 18 08 07 11 08 9a 1f 10 28 4e ?? ?? ?? 6f 4f ?? ?? ?? 00 11 08 17 58 13 08 11 08 20 00 ea 00 00 fe 04 13 09 11 09 2d d9 28 50 ?? ?? ?? 08 6f 51 ?? ?? ?? 6f 52 ?? ?? ?? 0d 09 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}