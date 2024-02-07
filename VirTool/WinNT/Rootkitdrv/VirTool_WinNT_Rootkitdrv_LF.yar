
rule VirTool_WinNT_Rootkitdrv_LF{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.LF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 45 00 58 00 58 00 } //01 00  \Device\WINDOWSEXX
		$a_03_1 = {8b 7d 0c 8b 47 60 8b 48 0c 8b 58 10 8b 77 3c 8b 40 04 89 45 90 01 01 81 f9 d7 e0 22 00 0f 85 90 00 } //01 00 
		$a_03_2 = {8b 7d 0c 8b 45 90 01 01 85 c0 75 08 8b 4d 90 01 01 89 4f 1c eb 04 83 67 1c 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}