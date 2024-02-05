
rule VirTool_WinNT_Rootkitdrv_CL{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.CL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {25 00 73 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 00 00 00 00 65 78 70 } //01 00 
		$a_01_1 = {6a 04 8d 45 fc 50 6a 0b ff d6 3d 04 00 00 c0 75 2d 68 44 64 6b 20 } //01 00 
		$a_01_2 = {74 4a 8b 47 3c 8b 44 38 78 83 65 08 00 03 c7 8b 48 18 } //01 00 
		$a_01_3 = {83 c0 14 89 01 66 81 38 0b 01 75 10 8b 4c 24 10 05 e0 00 } //00 00 
	condition:
		any of ($a_*)
 
}