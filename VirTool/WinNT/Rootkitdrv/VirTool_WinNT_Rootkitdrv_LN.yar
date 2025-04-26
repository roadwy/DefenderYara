
rule VirTool_WinNT_Rootkitdrv_LN{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.LN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 } //1 \Registry\Machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion
		$a_03_1 = {33 ff 89 7d ?? 89 7d ?? c7 45 ?? 47 90 90 a4 db 66 c7 45 ?? 40 1d 66 c7 45 ?? bd 4c c6 45 ?? 9e c6 45 ?? e4 c6 45 ?? f4 c6 45 ?? 8c c6 45 ?? e4 c6 45 ?? 91 c6 45 ?? 95 c6 45 ?? 28 8b 75 08 8d 46 08 80 38 00 74 } //1
		$a_03_2 = {8b 4c 24 0c 8b 01 3d 13 01 00 00 75 14 8d 81 88 00 00 00 ff b0 d0 07 00 00 50 e8 ?? ?? ff ff eb 2a 3d 11 01 00 00 75 ?? e8 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}