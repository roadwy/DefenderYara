
rule Trojan_Win64_CobaltStrike_WJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.WJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c1 83 e0 ?? 83 e1 ?? 99 41 01 c8 41 f7 f8 01 c8 69 c0 ?? ?? ?? ?? 45 31 c0 31 c9 ba ?? ?? ?? ?? 48 98 48 6b c0 ?? 48 89 44 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}