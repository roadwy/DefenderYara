
rule TrojanDownloader_Win32_Tabmngr_A{
	meta:
		description = "TrojanDownloader:Win32/Tabmngr.A,SIGNATURE_TYPE_PEHSTR_EXT,21 00 1e 00 06 00 00 "
		
	strings :
		$a_00_0 = {6e 6f 67 61 72 69 63 61 73 74 2e 63 6f 6d 2f 70 6f 6c 69 63 65 2e 70 68 70 3f 6c 75 6e 63 68 65 72 3d 25 46 4f 4c 44 45 52 } //10 nogaricast.com/police.php?luncher=%FOLDER
		$a_00_1 = {25 44 4f 4d 41 49 4e 25 6c 6f 67 2d 62 69 6e 2f 6c 75 6e 63 68 5f 6c 6f 61 64 2e 70 68 70 3f 61 66 66 5f 69 64 3d 25 41 46 46 49 44 26 6c 75 6e 63 68 5f 69 64 3d 25 4c 55 4e 43 48 49 44 26 6d 61 64 64 72 3d 25 4d 41 43 41 44 44 52 } //10 %DOMAIN%log-bin/lunch_load.php?aff_id=%AFFID&lunch_id=%LUNCHID&maddr=%MACADDR
		$a_00_2 = {25 44 4f 4d 41 49 4e 25 6c 6f 67 2d 62 69 6e 2f 6c 75 6e 63 68 5f 69 6e 73 74 61 6c 6c 2e 70 68 70 3f 61 66 66 5f 69 64 3d 25 41 46 46 49 44 26 6c 75 6e 63 68 5f 69 64 3d 25 4c 55 4e 43 48 49 44 26 6d 61 64 64 72 3d 25 4d 41 43 41 44 44 52 26 61 63 74 69 6f 6e 3d 25 41 43 54 49 4f 4e } //10 %DOMAIN%log-bin/lunch_install.php?aff_id=%AFFID&lunch_id=%LUNCHID&maddr=%MACADDR&action=%ACTION
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
		$a_01_4 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_01_5 = {49 6e 74 65 72 6e 65 74 43 6c 6f 73 65 48 61 6e 64 6c 65 } //1 InternetCloseHandle
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=30
 
}