
rule Trojan_Win32_Ursnif_YZ_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.YZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 5c 6b d2 47 0f b6 c3 2b c2 99 2b c8 19 15 ?? ?? ?? ?? eb 22 8b 44 24 5c 8a d8 6b c0 30 02 d9 80 eb 09 0f b6 cb 2b c1 99 88 1d ?? ?? ?? ?? 8b c8 89 15 ?? ?? ?? ?? 83 7c 24 24 08 89 0d ?? ?? ?? ?? 73 7a 66 0f b6 f3 66 6b f6 06 66 03 f1 0f b7 d6 8b c2 6b c0 60 3d 4f 21 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}