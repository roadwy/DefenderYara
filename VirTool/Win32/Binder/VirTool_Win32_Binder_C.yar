
rule VirTool_Win32_Binder_C{
	meta:
		description = "VirTool:Win32/Binder.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 8d 94 24 90 01 02 00 00 6a 1a 52 6a 00 ff 15 90 01 04 ff d6 bf 90 01 04 83 c9 ff 90 00 } //01 00 
		$a_00_1 = {5c 6d 69 63 72 6f 73 6f 66 74 5c 77 75 61 75 63 6c 74 2e 65 78 65 00 } //01 00 
		$a_03_2 = {3e 3e 4e 55 4c 90 02 05 2f 63 20 64 65 6c 20 90 02 02 43 6f 6d 53 70 65 63 90 00 } //01 00 
		$a_01_3 = {28 2a 2e 70 64 66 29 7c 2a 2e 70 64 66 7c } //00 00  (*.pdf)|*.pdf|
	condition:
		any of ($a_*)
 
}