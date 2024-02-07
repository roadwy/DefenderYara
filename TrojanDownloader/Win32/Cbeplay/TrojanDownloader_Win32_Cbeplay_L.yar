
rule TrojanDownloader_Win32_Cbeplay_L{
	meta:
		description = "TrojanDownloader:Win32/Cbeplay.L,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 6f 3d 25 73 26 6f 73 3d 25 64 26 76 65 72 3d 25 53 26 69 64 78 3d 25 73 26 75 73 65 72 3d 25 53 } //01 00  geo=%s&os=%d&ver=%S&idx=%s&user=%S
		$a_01_1 = {44 37 45 42 36 30 38 35 2d 45 37 30 41 2d 34 66 35 61 2d 39 39 32 31 2d 45 36 42 44 32 34 34 41 38 43 31 37 } //01 00  D7EB6085-E70A-4f5a-9921-E6BD244A8C17
		$a_01_2 = {25 73 26 69 6f 63 74 6c 3d 25 64 26 64 61 74 61 3d 25 73 } //01 00  %s&ioctl=%d&data=%s
		$a_01_3 = {2f 71 20 2f 63 20 66 6f 72 20 2f 6c 20 25 25 69 20 69 6e 20 28 31 2c 31 2c 34 30 30 30 30 30 30 30 30 30 29 20 64 6f 20 69 66 20 6e 6f 74 20 65 78 69 73 74 20 22 25 73 22 20 28 65 78 69 74 29 } //00 00  /q /c for /l %%i in (1,1,4000000000) do if not exist "%s" (exit)
	condition:
		any of ($a_*)
 
}