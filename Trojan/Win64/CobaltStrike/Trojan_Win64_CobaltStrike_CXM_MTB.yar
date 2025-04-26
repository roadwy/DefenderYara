
rule Trojan_Win64_CobaltStrike_CXM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 ea 8d 04 0a 89 c2 c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 c1 e0 ?? 29 d0 89 ca 29 c2 48 63 c2 48 03 85 ?? ?? ?? ?? 0f b6 00 44 31 c8 41 88 00 83 85 ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 48 63 d0 48 8b 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}