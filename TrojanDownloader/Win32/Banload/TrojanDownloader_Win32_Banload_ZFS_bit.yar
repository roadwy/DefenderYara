
rule TrojanDownloader_Win32_Banload_ZFS_bit{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZFS!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //1 Software\Microsoft\Windows\CurrentVersion\RunOnce
		$a_01_1 = {2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 62 79 70 61 73 73 20 2d 6e 6f 70 72 6f 66 69 6c 65 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 -ExecutionPolicy bypass -noprofile -windowstyle hidden (New-Object System.Net.WebClient).DownloadFile
		$a_03_2 = {68 74 74 70 3a 2f 2f 90 02 50 2e 6f 6e 69 6f 6e 2e 6c 69 6e 6b 2f 90 02 20 2e 63 73 73 90 00 } //1
		$a_03_3 = {25 54 45 4d 50 25 5c 90 02 20 2e 65 78 65 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}