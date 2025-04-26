
rule Trojan_Win32_CobaltStrike_PBH_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.PBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 89 c0 f7 e9 c1 fa 02 44 89 c0 c1 f8 1f 29 c2 8d 04 d2 01 c0 44 89 c7 29 c7 89 f8 48 98 48 8b 15 ?? ?? ?? ?? 0f b6 14 02 42 32 94 04 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 42 88 14 00 49 83 c0 01 4d 39 c8 75 bb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}