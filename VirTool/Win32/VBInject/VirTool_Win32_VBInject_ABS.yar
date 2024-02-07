
rule VirTool_Win32_VBInject_ABS{
	meta:
		description = "VirTool:Win32/VBInject.ABS,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 8b 0d 90 01 04 c7 04 c1 43 61 6c 6c c7 44 c1 04 57 69 6e 64 90 00 } //01 00 
		$a_03_1 = {8b 45 fc 8b 0d 90 01 04 c7 04 c1 56 69 72 74 c7 44 c1 04 75 61 6c 50 90 00 } //01 00 
		$a_03_2 = {8b 45 fc 8b 0d 90 01 04 c7 04 c1 6f 77 50 72 c7 44 c1 04 6f 63 57 00 90 00 } //01 00 
		$a_03_3 = {8b 45 fc 8b 0d 90 01 04 c7 04 c1 6c 73 74 72 c7 44 c1 04 6c 65 6e 57 90 00 } //04 00 
		$a_00_4 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //00 00  MSVBVM60.DLL
	condition:
		any of ($a_*)
 
}