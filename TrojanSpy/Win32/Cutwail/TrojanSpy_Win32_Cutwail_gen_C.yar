
rule TrojanSpy_Win32_Cutwail_gen_C{
	meta:
		description = "TrojanSpy:Win32/Cutwail.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {66 3d 19 00 74 14 33 c9 66 8b 0e 51 ff d7 66 3d 19 00 } //02 00 
		$a_02_1 = {68 00 24 40 9c 56 ff 15 90 01 04 56 90 00 } //01 00 
		$a_00_2 = {64 61 74 61 3d 25 73 00 } //01 00 
		$a_00_3 = {6d 61 69 6c 73 70 65 63 74 72 65 00 } //01 00 
		$a_00_4 = {53 4d 54 50 44 52 56 00 } //00 00 
	condition:
		any of ($a_*)
 
}