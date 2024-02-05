
rule VirTool_Win32_Goodump_MTB{
	meta:
		description = "VirTool:Win32/Goodump!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 6a 00 6a 00 6a 00 8d 45 90 01 01 50 ff 90 00 } //01 00 
		$a_00_1 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c } //01 00 
		$a_02_2 = {53 45 4c 45 43 54 90 02 20 61 63 74 69 6f 6e 5f 75 72 6c 2c 90 02 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 90 02 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 90 02 20 46 52 4f 4d 90 02 20 6c 6f 67 69 6e 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}