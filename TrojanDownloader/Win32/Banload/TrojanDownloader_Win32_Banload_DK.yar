
rule TrojanDownloader_Win32_Banload_DK{
	meta:
		description = "TrojanDownloader:Win32/Banload.DK,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0d 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 4f 46 54 57 41 52 45 5c 4d 49 43 52 4f 53 4f 46 54 5c 57 49 4e 44 4f 57 53 5c 43 55 52 52 45 4e 54 56 45 52 53 49 4f 4e 5c 52 55 4e 5c } //01 00  HKEY_CURRENT_USER\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN\
		$a_00_1 = {59 6f 75 54 75 62 65 2e 63 6f 6d } //01 00  YouTube.com
		$a_00_2 = {46 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 5c 00 44 00 42 00 5c 00 } //01 00  Firewall\DB\
		$a_00_3 = {4e 00 4f 00 44 00 20 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //0a 00  NOD Protection
		$a_02_4 = {55 8b ec 83 ec 0c 68 90 01 04 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 50 53 56 57 89 65 f4 c7 45 f8 90 01 04 33 f6 89 75 fc 8b 45 08 50 8b 08 ff 51 04 68 90 01 04 89 75 dc 89 75 d8 89 75 c4 89 75 c0 89 75 bc 89 75 b8 89 75 a8 e8 90 01 04 66 85 c0 0f 85 90 01 04 8b 3d 90 01 04 8d 55 a8 8d 4d c4 c7 45 b0 90 01 04 c7 45 a8 08 00 00 00 ff d7 8b 1d 90 01 04 ba 90 01 04 8d 4d d8 ff d3 ff 15 90 01 04 8b 55 d8 56 56 8b 35 90 01 04 8d 45 b8 52 50 ff d6 8d 4d c4 50 8d 55 c0 51 52 ff 15 90 01 04 50 8d 45 bc 50 ff d6 50 6a 00 e8 90 01 04 ff 15 90 01 04 8b 4d b8 8d 55 d8 51 52 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}