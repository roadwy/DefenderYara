
rule Backdoor_Win32_Phdet_gen_A{
	meta:
		description = "Backdoor:Win32/Phdet.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 0a 00 00 05 00 "
		
	strings :
		$a_02_0 = {e9 75 01 00 00 6a 03 68 90 01 04 56 e8 90 01 02 00 00 83 c4 0c 85 c0 75 18 e8 90 01 02 ff ff 68 90 01 04 ff 15 90 01 04 6a 00 90 00 } //05 00 
		$a_02_1 = {c7 85 d0 fb ff ff 01 00 01 00 8d 85 d0 fb ff ff 50 8b 8d ec fe ff ff 51 ff 15 90 01 04 8b 55 08 89 95 88 fc ff ff 90 00 } //05 00 
		$a_02_2 = {74 6e 53 8b 1d 90 01 04 55 6a fe ff d3 8b 2d 90 01 04 50 ff d5 6a 00 68 90 01 04 e8 90 01 02 ff ff 68 90 01 04 56 e8 90 00 } //01 00 
		$a_02_3 = {8d 54 24 04 cd 2e c2 14 00 b8 01 00 00 00 c2 14 00 90 09 0e 00 83 3d 90 01 04 00 74 0e a1 90 00 } //01 00 
		$a_01_4 = {8b cc 0f 34 c3 } //01 00 
		$a_02_5 = {fa 9c 60 ff 15 90 01 04 61 9d ba 90 01 04 0f 35 90 00 } //01 00 
		$a_01_6 = {25 64 2e 25 64 2e 25 64 2e 25 64 00 25 64 2e } //01 00 
		$a_01_7 = {64 69 65 00 } //01 00  楤e
		$a_01_8 = {66 6c 6f 6f 64 00 } //01 00  汦潯d
		$a_01_9 = {26 62 75 69 6c 64 5f 69 64 3d 25 73 } //00 00  &build_id=%s
	condition:
		any of ($a_*)
 
}