
rule Backdoor_Win32_Heloag_B{
	meta:
		description = "Backdoor:Win32/Heloag.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {83 c8 80 40 88 44 3c 90 01 01 47 83 ff 02 7c e4 90 00 } //01 00 
		$a_00_1 = {68 65 6c 6c 6f 41 67 65 6e 74 } //01 00 
		$a_00_2 = {25 64 2d 25 64 2d 25 64 2d 25 64 2d 25 64 2e 68 74 6d } //01 00 
		$a_00_3 = {25 73 5c 25 64 2d 25 64 2d 25 64 2d 25 64 2d 25 64 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}