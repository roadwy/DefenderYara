
rule Worm_Win32_Woriply_gen_A{
	meta:
		description = "Worm:Win32/Woriply.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 04 00 00 04 00 "
		
	strings :
		$a_01_0 = {31 46 47 4e 2d 39 44 4e 4e 2d 32 48 4c 5a 2d 4c 39 4d 4b 2d 52 38 44 48 2d 49 38 34 4a } //01 00 
		$a_01_1 = {73 65 72 76 69 63 65 4e 61 6d 65 3d 73 76 63 61 67 65 6e 74 0a } //01 00 
		$a_01_2 = {6d 61 69 6e 63 6c 61 73 73 3d 42 61 63 6b 75 70 4d 6f 6e 69 74 6f 72 0a } //02 00 
		$a_01_3 = {6d 61 69 6e 63 6c 61 73 73 3d 6d 75 6c 74 69 70 6c 79 0a } //00 00 
	condition:
		any of ($a_*)
 
}