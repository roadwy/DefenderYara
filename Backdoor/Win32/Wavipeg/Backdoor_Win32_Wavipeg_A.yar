
rule Backdoor_Win32_Wavipeg_A{
	meta:
		description = "Backdoor:Win32/Wavipeg.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 74 2f 73 69 2e 70 68 70 3f } //01 00 
		$a_01_1 = {61 76 70 00 65 73 65 74 00 65 67 75 69 } //01 00 
		$a_01_2 = {25 73 3d 64 64 6f 73 26 63 6f 6d 70 3d 25 73 } //01 00 
		$a_01_3 = {26 63 6f 6d 70 3d 25 73 26 65 78 74 3d } //01 00 
		$a_01_4 = {3c 42 4b 3e 00 3c 44 4f 57 4e 3e } //00 00 
	condition:
		any of ($a_*)
 
}