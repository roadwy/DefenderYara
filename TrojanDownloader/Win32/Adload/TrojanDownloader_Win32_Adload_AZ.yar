
rule TrojanDownloader_Win32_Adload_AZ{
	meta:
		description = "TrojanDownloader:Win32/Adload.AZ,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {8b f7 8b d9 8b fa 83 c9 ff f2 ae 8b cb 4f c1 e9 02 f3 a5 8b cb 8d 94 24 1c 01 00 00 83 e1 03 f3 a4 bf 90 01 04 83 c9 ff f2 ae f7 d1 2b f9 8b f7 8b d9 8b fa 83 c9 ff f2 ae 8b cb 4f c1 e9 02 f3 a5 8b cb 8d 84 24 1c 01 00 00 83 e1 03 50 f3 a4 90 00 } //1
		$a_00_1 = {68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 70 6f 77 65 72 63 72 65 61 74 6f 72 } //1 http://download.powercreator
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c 7b 35 42 30 32 45 42 41 31 2d 45 46 44 44 2d 34 37 37 44 2d 41 33 37 46 2d 30 35 33 38 33 31 36 35 43 39 43 30 7d } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{5B02EBA1-EFDD-477D-A37F-05383165C9C0}
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 70 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run
		$a_00_4 = {41 75 74 6f 55 70 2e 65 78 65 } //1 AutoUp.exe
		$a_00_5 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 6c 78 75 70 } //1 http://www.alxup
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}