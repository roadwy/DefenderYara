
rule TrojanDownloader_Win32_Small_MB_MTB{
	meta:
		description = "TrojanDownloader:Win32/Small.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {33 db 88 44 24 10 b2 78 88 4c 24 15 88 44 24 16 88 4c 24 17 88 44 24 19 88 44 24 1b b9 3d 00 00 00 33 c0 8d 7c 24 1d 88 54 24 11 c6 44 24 12 70 c6 44 24 13 6c c6 44 24 14 6f c6 44 24 18 2e 88 54 24 1a 88 5c 24 1c } //01 00 
		$a_01_1 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 } //01 00  CreateProcessA
		$a_01_2 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //00 00  CreateToolhelp32Snapshot
	condition:
		any of ($a_*)
 
}