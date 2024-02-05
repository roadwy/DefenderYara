
rule Backdoor_Win32_Onklew_A{
	meta:
		description = "Backdoor:Win32/Onklew.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 6e 6c 79 4f 6e 65 4b 65 77 } //01 00 
		$a_01_1 = {52 75 6e 55 72 6c 4b 65 77 } //01 00 
		$a_01_2 = {64 6e 73 63 6b 2e 68 6f 75 73 66 2e 6e 65 74 } //01 00 
		$a_03_3 = {47 53 4e 61 6d 65 3d 90 02 0c 53 79 73 3d 90 02 0c 50 63 4e 61 6d 65 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}