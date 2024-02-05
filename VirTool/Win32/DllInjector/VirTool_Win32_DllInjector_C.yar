
rule VirTool_Win32_DllInjector_C{
	meta:
		description = "VirTool:Win32/DllInjector.C,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 00 } //01 00 
		$a_01_1 = {81 f9 5b bc 4a 6a 0f 85 } //01 00 
		$a_03_2 = {8e 4e 0e ec 74 90 01 04 aa fc 0d 7c 74 90 01 04 54 ca af 91 74 90 01 04 ef ce e0 60 90 00 } //01 00 
		$a_03_3 = {81 f9 5d 68 fa 3c 0f 85 90 01 01 00 00 00 90 00 } //01 00 
		$a_01_4 = {b8 0a 4c 53 75 } //01 00 
		$a_03_5 = {3c 33 c9 41 b8 00 30 00 00 90 01 01 03 90 01 01 44 8d 49 40 90 02 10 ff d5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}