
rule TrojanDownloader_Win32_Zlob_gen_AV{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!AV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 ec 20 53 56 57 33 f6 56 56 56 56 6a 64 6a 64 b8 00 08 00 00 50 50 68 00 00 00 10 56 68 90 01 02 40 00 68 80 00 00 08 ff 15 90 01 02 40 00 8b 5d 08 8b 3d 90 01 02 40 00 89 45 fc 83 c3 04 eb 14 8d 45 e0 50 ff 15 90 01 02 40 00 8d 45 e0 50 ff 15 90 01 02 40 00 6a 01 56 56 8d 45 e0 56 50 ff d7 85 c0 75 dd 68 ff 04 00 00 6a ff 56 53 6a 01 ff 15 90 01 02 40 00 83 f8 01 74 db 90 00 } //01 00 
		$a_02_1 = {2e 63 68 6c 5c 43 4c 53 49 44 90 05 04 01 00 7b 36 42 46 35 32 41 35 32 2d 33 39 34 41 2d 31 31 44 33 2d 42 31 35 33 2d 30 30 43 30 34 46 37 39 46 41 41 36 7d 90 00 } //01 00 
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 4e 65 74 50 72 6f 6a 65 63 74 } //00 00  Software\NetProject
	condition:
		any of ($a_*)
 
}