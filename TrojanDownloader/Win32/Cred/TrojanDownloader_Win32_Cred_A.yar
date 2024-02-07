
rule TrojanDownloader_Win32_Cred_A{
	meta:
		description = "TrojanDownloader:Win32/Cred.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 61 00 64 00 76 00 62 00 65 00 61 00 63 00 6f 00 6e 00 2e 00 6e 00 65 00 74 00 2f 00 61 00 64 00 76 00 2e 00 70 00 68 00 70 00 3f 00 69 00 3d 00 90 02 04 26 00 72 00 6e 00 64 00 3d 00 90 00 } //01 00 
		$a_02_1 = {68 74 74 70 3a 2f 2f 61 64 76 62 65 61 63 6f 6e 2e 6e 65 74 2f 61 64 76 2e 70 68 70 3f 69 3d 90 02 04 26 72 6e 64 3d 90 00 } //01 00 
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {53 00 4f 00 46 00 54 00 57 00 41 00 43 00 3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 } //01 00  SOFTWAC:\TEMP\
		$a_02_4 = {8d 85 70 fe ff ff 50 ff d6 83 f8 ff 74 04 a8 10 74 31 8d 85 68 fd ff ff 50 ff d6 83 f8 ff 74 04 a8 10 74 1f 8d 85 58 fb ff ff 50 ff d6 83 f8 ff 74 04 a8 10 74 0d 8d 9d 50 f9 ff ff e8 17 fc ff ff 33 db 8b 35 90 01 04 6a 01 8d 85 70 fe ff ff 50 8d 85 60 fc ff ff 50 ff d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}