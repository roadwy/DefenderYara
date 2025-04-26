
rule Trojan_Win32_Redline_NW_MTB{
	meta:
		description = "Trojan:Win32/Redline.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 02 33 c1 8b 0d ?? ?? ?? ?? 03 4d 08 88 01 8b e5 5d c3 90 0a 35 00 0f b6 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 08 } //10
		$a_80_1 = {63 75 61 62 6e 6a 66 67 75 71 62 69 75 } //cuabnjfguqbiu  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}