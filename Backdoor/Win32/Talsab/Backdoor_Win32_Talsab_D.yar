
rule Backdoor_Win32_Talsab_D{
	meta:
		description = "Backdoor:Win32/Talsab.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 30 35 2e 32 35 31 2e 31 34 30 2e 31 } //01 00 
		$a_03_1 = {64 65 73 74 69 6e 6f 3d 90 02 2f 75 73 65 72 3d 90 02 2f 26 69 63 65 72 69 6b 3d 90 00 } //01 00 
		$a_01_2 = {66 64 77 61 71 65 36 32 33 } //01 00 
		$a_02_3 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 90 01 04 ed 81 fb 68 58 4d 56 0f 94 45 ff 5b 59 5a 33 c0 5a 59 59 64 89 10 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}