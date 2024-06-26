
rule TrojanDownloader_Win32_Seimon_D{
	meta:
		description = "TrojanDownloader:Win32/Seimon.D,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0a 00 00 02 00 "
		
	strings :
		$a_03_0 = {6c 6f 67 2f 70 72 6f 63 2e 70 68 70 3f 90 02 0a 6b 65 79 3d 25 90 02 08 49 44 90 00 } //02 00 
		$a_02_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 90 02 0a 2e 63 6f 6d 2f 62 69 6e 2f 90 02 0a 2e 70 68 70 90 00 } //01 00 
		$a_01_2 = {6d 75 74 65 78 5f } //01 00  mutex_
		$a_01_3 = {25 4d 41 43 41 44 44 52 } //01 00  %MACADDR
		$a_01_4 = {25 73 5c 6d 73 61 67 65 6e 74 5c 25 73 } //01 00  %s\msagent\%s
		$a_01_5 = {25 73 5f 6d 74 78 5f 6e 61 6d 65 } //01 00  %s_mtx_name
		$a_01_6 = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d 0d 0a 55 52 4c 3d 25 73 0d 0a 49 63 6f 6e 49 6e 64 65 78 3d 30 0d 0a 49 63 6f 6e 46 69 6c 65 3d 25 73 } //01 00 
		$a_01_7 = {25 41 43 54 49 4f 4e } //01 00  %ACTION
		$a_01_8 = {25 43 4f 4d 50 41 4e 59 } //01 00  %COMPANY
		$a_01_9 = {25 73 5c 25 64 2e 65 78 65 } //00 00  %s\%d.exe
	condition:
		any of ($a_*)
 
}