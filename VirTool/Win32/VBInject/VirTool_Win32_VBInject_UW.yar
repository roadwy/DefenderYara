
rule VirTool_Win32_VBInject_UW{
	meta:
		description = "VirTool:Win32/VBInject.UW,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 02 00 "
		
	strings :
		$a_03_0 = {3c d3 8d 95 50 ff ff ff 8d 45 94 52 8d 4d d4 50 51 ff d7 50 8d 55 b4 8d 45 d8 52 50 ff d7 50 90 09 33 00 ff ff b0 ff 15 90 01 02 40 00 89 85 08 ff ff ff 8b 85 50 ff ff ff b9 04 00 00 00 c7 85 00 ff ff ff 03 00 00 00 2b 48 14 8d 95 00 ff ff ff c1 e1 04 03 48 0c 90 00 } //02 00 
		$a_01_1 = {26 00 48 00 35 00 39 00 35 00 } //02 00  &H595
		$a_01_2 = {26 00 48 00 36 00 38 00 } //02 00  &H68
		$a_01_3 = {26 00 48 00 45 00 38 00 } //02 00  &HE8
		$a_01_4 = {26 00 48 00 43 00 33 00 } //01 00  &HC3
		$a_01_5 = {35 00 39 00 35 00 38 00 } //01 00  5958
		$a_01_6 = {26 00 48 00 35 00 00 00 35 00 39 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}