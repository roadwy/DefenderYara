
rule Trojan_Win32_CobaltStrike_ZZ_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.ZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 0f b6 c0 41 83 c0 01 b8 ?? ?? ?? ?? 41 f7 e8 41 03 d0 c1 fa 09 8b c2 c1 e8 1f 03 d0 69 d2 ?? ?? 00 00 44 2b c2 41 0f b6 f8 42 0f b6 0c 1f 41 0f b6 c1 03 c8 b8 90 1b 00 f7 e9 03 d1 c1 fa 09 8b c2 c1 e8 1f 03 d0 69 d2 90 1b 01 00 00 44 8b c9 44 2b ca 41 0f b6 d1 42 0f b6 0c 1f 42 0f b6 04 1a 42 88 04 1f 42 88 0c 1a 0f b6 c9 42 0f b6 04 1f 03 c8 b8 90 1b 00 f7 e9 03 d1 c1 fa 09 8b c2 c1 e8 1f 03 d0 69 d2 90 1b 01 00 00 2b ca 8b 05 ?? ?? ?? ?? f7 d8 48 63 d0 49 03 d4 0f b6 c1 42 0f b6 0c 18 42 30 0c 3a 49 83 c4 01 48 83 eb 01 74 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}