
rule Backdoor_Win32_Pabosp{
	meta:
		description = "Backdoor:Win32/Pabosp,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {8d 4c 24 08 51 ff 15 90 01 04 68 90 01 04 68 90 01 04 e8 90 01 04 84 c0 74 90 01 01 6a 05 68 90 01 04 ff 15 90 01 04 e8 90 01 04 8b 54 24 04 8b 44 24 00 89 42 04 b0 01 90 00 } //02 00 
		$a_00_1 = {61 76 67 73 70 2e 65 78 65 } //02 00  avgsp.exe
		$a_00_2 = {4d 61 6b 65 41 6e 64 53 68 6f 77 45 67 67 } //02 00  MakeAndShowEgg
		$a_00_3 = {44 65 6c 65 74 65 4d 79 73 65 6c 66 } //00 00  DeleteMyself
	condition:
		any of ($a_*)
 
}