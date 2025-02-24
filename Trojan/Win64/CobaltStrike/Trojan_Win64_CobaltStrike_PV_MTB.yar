
rule Trojan_Win64_CobaltStrike_PV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c6 41 ff c1 4d 8d 52 ?? 48 f7 e1 48 c1 ea ?? 48 8d 04 92 48 c1 e0 ?? 48 2b c8 48 03 cb 0f b6 44 0c ?? 43 32 44 13 ?? 41 88 42 ?? 41 81 f9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_PV_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.PV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 ff c0 89 04 24 48 63 04 24 48 3d [0-04] 73 ?? 48 63 04 ?? 48 8d 0d ?? ?? ?? ?? 0f b6 04 01 03 44 24 ?? 33 44 24 ?? 48 63 0c 24 48 8d 15 ?? ?? ?? ?? 88 04 0a eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}