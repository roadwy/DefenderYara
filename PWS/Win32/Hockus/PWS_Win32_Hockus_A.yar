
rule PWS_Win32_Hockus_A{
	meta:
		description = "PWS:Win32/Hockus.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 c9 ff 33 c0 f2 ae f7 d1 83 c1 ff 89 4d cc c7 45 ec ff ff ff ff } //01 00 
		$a_01_1 = {50 61 73 73 77 6f 72 64 3a } //01 00 
		$a_00_2 = {6e 65 74 73 68 22 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 70 6f 72 74 6f 70 65 6e 69 6e 67 20 54 43 50 20 00 } //01 00 
		$a_00_3 = {75 70 67 72 61 64 65 2e 74 78 74 3f 73 69 67 6e 3d } //01 00 
		$a_00_4 = {72 62 6c 2e 74 78 74 3f 73 69 67 6e 3d } //00 00 
	condition:
		any of ($a_*)
 
}