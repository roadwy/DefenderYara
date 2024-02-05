
rule Trojan_Win32_Redline_NW_MTB{
	meta:
		description = "Trojan:Win32/Redline.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 02 33 c1 8b 0d 90 01 04 03 4d 08 88 01 8b e5 5d c3 90 0a 35 00 0f b6 0d 90 01 04 8b 15 90 01 04 03 55 08 90 00 } //01 00 
		$a_80_1 = {63 75 61 62 6e 6a 66 67 75 71 62 69 75 } //cuabnjfguqbiu  00 00 
	condition:
		any of ($a_*)
 
}