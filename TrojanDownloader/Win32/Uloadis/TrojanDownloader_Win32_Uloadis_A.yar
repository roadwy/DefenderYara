
rule TrojanDownloader_Win32_Uloadis_A{
	meta:
		description = "TrojanDownloader:Win32/Uloadis.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //01 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_00_1 = {64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //01 00  drivers\etc\hosts
		$a_00_2 = {53 65 74 45 6e 74 72 69 65 73 49 6e 41 63 6c 41 00 } //02 00 
		$a_00_3 = {5b c3 6e 74 6f 73 6b 72 6e 6c 2e 65 78 65 00 00 00 00 4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 00 00 00 00 55 8b ec 33 } //03 00 
		$a_03_4 = {be 00 40 00 00 6a 04 68 00 30 00 00 56 6a 00 e8 90 01 02 ff ff 8b d8 85 db 74 45 6a 00 56 53 55 e8 90 01 02 ff ff 8b f8 81 ff 04 00 00 c0 75 13 68 00 80 00 00 90 00 } //01 00 
		$a_03_5 = {66 81 3b 4d 5a 75 90 01 01 03 43 3c 0f b7 48 14 81 f9 e0 00 00 00 75 90 01 01 8b d0 83 c2 18 8b ca 81 c1 e0 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}