
rule TrojanDownloader_Win32_Cbeplay_R{
	meta:
		description = "TrojanDownloader:Win32/Cbeplay.R,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 71 20 2f 63 20 66 6f 72 20 2f 6c 20 25 25 69 20 69 6e 20 28 31 2c 31 2c 34 30 30 30 30 30 30 30 30 30 29 20 64 6f 20 69 66 20 6e 6f 74 20 65 78 69 73 74 } //1 /q /c for /l %%i in (1,1,4000000000) do if not exist
		$a_03_1 = {0f b7 0f 8b c1 25 00 f0 00 00 3d 00 30 00 00 75 14 81 e1 ff 0f 00 00 03 0a 3b 4e 50 77 ?? 8b 44 24 10 01 04 29 8b 4a 04 83 e9 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}