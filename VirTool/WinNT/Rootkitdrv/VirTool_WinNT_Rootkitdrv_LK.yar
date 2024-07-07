
rule VirTool_WinNT_Rootkitdrv_LK{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.LK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 4b 00 6e 00 6f 00 77 00 6e 00 44 00 6c 00 6c 00 73 00 5c 00 4b 00 6e 00 6f 00 77 00 6e 00 44 00 6c 00 6c 00 50 00 61 00 74 00 68 00 } //1 \KnownDlls\KnownDllPath
		$a_03_1 = {8b 4d f4 8b 41 08 8b 78 08 8b 40 0c 89 7d 90 01 01 89 45 90 01 01 ff 15 90 01 04 8d 45 90 01 01 50 53 53 6a 70 53 53 8d 45 90 01 01 50 90 00 } //1
		$a_03_2 = {89 46 50 8b 46 60 89 5e 64 83 e8 24 c6 00 03 c6 40 01 00 8b 4b 08 8b 49 08 89 48 14 8b 4d 14 89 48 04 8b 4d 18 89 58 18 8b 11 89 50 0c 8b 49 04 89 48 10 8b 46 60 83 e8 24 c7 40 1c 90 01 04 89 78 20 c6 40 03 e0 8b 43 08 8b 48 08 8b d6 ff 15 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}