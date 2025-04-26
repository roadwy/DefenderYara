
rule TrojanDownloader_Win32_Kaohit_A{
	meta:
		description = "TrojanDownloader:Win32/Kaohit.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 44 6f 77 6e 6c 6f 61 64 28 61 72 73 69 76 5f 73 69 74 65 2c 20 22 68 61 73 68 2e 74 78 74 22 2c 20 33 2c 20 31 29 } //1 GetDownload(arsiv_site, "hash.txt", 3, 1)
		$a_01_1 = {47 65 74 44 6f 77 6e 6c 6f 61 64 28 53 69 74 65 5f 4c 69 6e 6b 2c 20 22 62 67 2e 74 78 74 22 2c 20 33 2c 20 31 29 } //1 GetDownload(Site_Link, "bg.txt", 3, 1)
		$a_01_2 = {47 65 74 44 6f 77 6e 6c 6f 61 64 28 41 74 61 6b 5f 4c 69 6e 6b 2c 20 22 68 69 74 2e 65 78 65 22 2c 20 33 2c 20 31 29 } //1 GetDownload(Atak_Link, "hit.exe", 3, 1)
		$a_01_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 63 68 72 6f 6d 65 2e 65 78 65 20 2f 46 } //1 taskkill /IM chrome.exe /F
		$a_01_4 = {77 67 65 74 2e 65 78 65 20 2d 4f 20 22 25 41 5f 41 70 70 44 61 74 61 25 5c 61 72 73 69 76 2e 65 78 65 22 20 22 25 68 61 73 68 61 72 72 31 25 22 } //1 wget.exe -O "%A_AppData%\arsiv.exe" "%hasharr1%"
		$a_01_5 = {22 25 50 72 6f 67 72 61 6d 5f 50 61 74 68 25 22 20 2b 65 } //1 "%Program_Path%" +e
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}