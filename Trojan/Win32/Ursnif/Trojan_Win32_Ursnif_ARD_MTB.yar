
rule Trojan_Win32_Ursnif_ARD_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.ARD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 f8 8b 44 24 ?? 3b c7 74 ?? 8b df 0f af d9 6b db ?? 03 c3 89 44 24 ?? 81 ff ?? ?? ?? ?? 74 ?? b3 ?? f6 eb 83 c6 ?? 02 c1 81 fe ?? ?? ?? ?? 7c } //1
		$a_02_1 = {33 ff 2b e8 6a ?? 58 1b c7 03 cd 66 8b 2d ?? ?? ?? ?? 13 d0 8b c1 89 15 ?? ?? ?? ?? 6b c0 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}