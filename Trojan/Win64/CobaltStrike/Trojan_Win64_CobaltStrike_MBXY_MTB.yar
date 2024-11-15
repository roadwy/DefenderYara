
rule Trojan_Win64_CobaltStrike_MBXY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MBXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 ea 08 88 14 01 41 ff 81 ?? 00 00 00 49 63 89 ?? 00 00 00 49 8b 81 c8 00 00 00 44 88 04 01 41 ff 81 ?? 00 00 00 41 8b 41 40 41 8b 49 04 83 f1 01 0f af c1 41 89 41 40 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}