
rule TrojanDownloader_Win32_Zlob_ANF{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ANF,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 85 dc fe ff ff 6a 07 50 ff 15 90 01 04 8d 85 dc fe ff ff 50 e8 90 01 04 59 8d 45 f0 50 c7 45 f0 90 01 04 c7 45 f4 90 01 04 89 5d f8 89 5d fc ff 15 90 01 04 85 c0 75 15 8d 85 d8 fd ff ff 50 8d 85 dc fe ff ff 50 e8 90 01 04 59 59 5f 33 c0 5b c9 c2 10 00 90 00 } //01 00 
		$a_02_1 = {56 57 6a 04 33 f6 5f c7 05 90 01 04 30 00 00 00 68 90 01 04 68 90 01 04 c7 05 90 01 04 02 00 00 00 89 3d 90 01 04 89 35 90 01 04 89 35 90 01 04 89 35 90 01 04 89 35 90 01 04 ff 15 90 01 04 68 90 01 04 50 a3 90 01 04 89 3d 90 01 04 89 35 90 01 04 89 35 90 01 04 ff 15 90 01 04 83 7c 24 0c 01 7e 1d 8b 7c 24 10 39 77 04 74 14 68 d0 07 00 00 ff 15 90 01 04 ff 77 04 ff 15 90 01 04 6a 01 56 68 90 01 04 e8 90 01 04 83 c4 0c 33 c0 5f 5e c3 90 00 } //01 00 
		$a_02_2 = {55 8b ec 83 ec 14 8d 45 fc 57 50 8b f9 6a 28 ff 15 90 01 04 50 ff 15 90 01 04 8d 45 f0 c7 45 ec 01 00 00 00 50 68 90 01 04 6a 00 c7 45 f8 02 00 00 00 ff 15 90 01 04 6a 00 6a 00 8d 45 ec 6a 10 50 6a 00 ff 75 fc ff 15 90 01 04 8b c7 5f c9 c3 90 00 } //01 00 
		$a_01_3 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 } //01 00  AdjustTokenPrivileges
		$a_01_4 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //01 00  SeDebugPrivilege
		$a_01_5 = {52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 43 74 72 6c 48 61 6e 64 6c 65 72 41 } //01 00  RegisterServiceCtrlHandlerA
		$a_00_6 = {47 45 54 20 2f 25 73 20 48 54 54 50 2f 31 2e 31 } //01 00  GET /%s HTTP/1.1
		$a_00_7 = {47 72 65 65 6e 46 6c 6f 77 65 72 20 64 65 72 74 } //01 00  GreenFlower dert
		$a_01_8 = {5a 77 53 79 73 74 65 6d 44 65 62 75 67 43 6f 6e 74 72 6f 6c } //00 00  ZwSystemDebugControl
	condition:
		any of ($a_*)
 
}