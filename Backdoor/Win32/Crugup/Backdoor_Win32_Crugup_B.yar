
rule Backdoor_Win32_Crugup_B{
	meta:
		description = "Backdoor:Win32/Crugup.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 72 75 6c 65 20 6e 61 6d 65 3d 22 00 } //01 00 
		$a_01_1 = {22 20 70 72 6f 67 72 61 6d 3d 22 00 } //01 00 
		$a_01_2 = {22 20 64 69 72 3d 4f 75 74 20 61 63 74 69 6f 6e 3d 61 6c 6c 6f 77 00 } //05 00 
		$a_01_3 = {51 75 61 6e 74 00 } //00 00 
		$a_00_4 = {5d 04 00 00 f0 90 } //03 80 
	condition:
		any of ($a_*)
 
}