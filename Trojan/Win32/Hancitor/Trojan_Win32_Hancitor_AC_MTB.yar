
rule Trojan_Win32_Hancitor_AC_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c7 3b c8 74 ?? 28 8e ?? ?? ?? ?? 8a da 8a 3d ?? ?? ?? ?? 02 d9 8d ?? ?? 0f b6 c3 8b ?? ?? ?? 2b c8 81 c2 ?? ?? ?? ?? 03 d1 8b } //1
		$a_03_1 = {0f b6 c7 3b c1 77 ?? 8a fb 8a c3 c0 e3 03 02 c3 88 3d ?? ?? ?? ?? 8a da 2a d8 0f b6 d3 2b d1 83 ea 06 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}