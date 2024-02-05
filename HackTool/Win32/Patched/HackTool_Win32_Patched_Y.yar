
rule HackTool_Win32_Patched_Y{
	meta:
		description = "HackTool:Win32/Patched.Y,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 18 81 38 90 01 03 00 74 0c 89 1d 90 01 03 00 c7 00 90 01 03 00 68 90 01 03 00 c3 60 b9 20 00 00 00 8d 3d 90 01 03 00 8b 74 24 28 f3 a6 74 07 61 ff 25 90 01 03 00 61 b8 90 01 03 00 c2 08 00 90 00 } //01 00 
		$a_01_1 = {72 61 64 6c 6c 5f 48 61 73 54 68 65 50 72 6f 64 75 63 74 42 65 65 6e 50 75 72 63 68 61 73 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}