
rule TrojanSpy_Win32_Nivdort_DB{
	meta:
		description = "TrojanSpy:Win32/Nivdort.DB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c4 0c 68 90 90 5f 01 00 ff 15 90 01 02 44 00 90 00 } //01 00 
		$a_03_1 = {00 68 05 0d 00 00 ff 15 90 01 02 44 00 90 00 } //01 00 
		$a_03_2 = {44 00 68 e8 03 00 00 ff 15 90 01 02 44 00 90 03 03 01 0f b7 05 a1 90 01 02 90 04 01 02 44 45 00 90 00 } //01 00 
		$a_03_3 = {00 68 d0 07 00 00 ff 15 90 01 02 44 00 90 00 } //01 00 
		$a_03_4 = {68 50 c3 00 00 ff 15 90 01 02 44 00 90 03 02 01 c7 05 b8 90 00 } //01 00 
		$a_03_5 = {68 00 50 00 00 8d 85 f8 af ff ff 50 57 ff 15 90 01 02 44 00 90 00 } //01 00 
		$a_03_6 = {68 10 27 00 00 90 02 10 ff 15 90 01 02 44 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}