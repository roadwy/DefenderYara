
rule VirTool_Win32_Rootkit_BW{
	meta:
		description = "VirTool:Win32/Rootkit.BW,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_02_0 = {0f b7 0c 50 83 f1 90 01 01 8b 55 90 01 01 8b 45 10 66 89 0c 50 eb d6 90 00 } //01 00 
		$a_00_1 = {0f b7 51 06 83 ea 01 6b d2 28 } //02 00 
		$a_00_2 = {5c 69 33 38 36 5c 68 63 70 69 64 65 73 6b 2e 70 64 62 } //01 00 
		$a_00_3 = {42 61 73 65 4e 61 6d 65 64 4f 62 6a 65 63 74 73 5c 55 49 44 5f 31 33 32 39 31 34 37 36 30 32 5f 4d 49 45 } //01 00 
		$a_00_4 = {6d 52 6f 6f 74 5c 73 79 73 74 65 6d 33 32 5c 6b 65 72 6e 65 6c 33 32 2e 64 6c } //00 00 
	condition:
		any of ($a_*)
 
}