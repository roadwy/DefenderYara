
rule Trojan_Win32_Trickpak_DK_MTB{
	meta:
		description = "Trojan:Win32/Trickpak.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {c1 e2 06 03 d6 88 44 24 0f 0f b6 05 90 01 04 89 54 24 14 b2 03 f6 ea 8a 54 24 0f c1 e3 04 02 d0 c0 e2 06 89 5c 24 10 88 54 24 90 00 } //0a 00 
		$a_00_1 = {2b d1 69 d2 f0 00 00 00 83 c4 24 03 d3 ff d2 } //00 00 
	condition:
		any of ($a_*)
 
}