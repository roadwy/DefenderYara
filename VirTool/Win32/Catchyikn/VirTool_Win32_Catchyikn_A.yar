
rule VirTool_Win32_Catchyikn_A{
	meta:
		description = "VirTool:Win32/Catchyikn.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 63 68 6f 69 63 65 25 22 3d 3d 22 31 22 20 67 6f 74 6f 20 54 43 50 0d 0a 69 66 20 2f 69 20 22 25 63 68 6f 69 63 65 25 22 3d 3d 22 32 22 20 67 6f 74 6f 20 53 59 4e 0d 0a 69 66 20 2f 69 20 22 } //01 00 
		$a_01_1 = {65 6f 6c 3d 50 20 74 6f 6b 65 6e 73 3d 31 20 64 65 6c 69 6d 73 3d 20 22 20 25 25 69 20 69 6e 20 28 73 31 2e 74 78 74 29 } //01 00 
		$a_01_2 = {5b 32 30 30 38 20 56 69 70 20 31 2e 30 5d } //00 00 
	condition:
		any of ($a_*)
 
}