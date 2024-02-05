
rule PWS_Win32_Frethog_BS{
	meta:
		description = "PWS:Win32/Frethog.BS,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {4b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 68 66 90 02 06 2e 64 6c 4c 90 00 } //01 00 
		$a_00_1 = {4b 52 5f 44 4c 4c 2e 64 6c 6c 00 47 4f 4f 44 42 4f 59 } //01 00 
		$a_00_2 = {73 62 61 6e 6e 65 72 3d 79 65 73 26 6c 6f 67 69 6e 6e 61 6d 65 3d 64 66 } //01 00 
		$a_00_3 = {00 64 6e 66 2e 65 78 65 00 45 72 72 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}