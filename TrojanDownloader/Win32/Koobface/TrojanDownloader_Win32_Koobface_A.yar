
rule TrojanDownloader_Win32_Koobface_A{
	meta:
		description = "TrojanDownloader:Win32/Koobface.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {64 65 6c 20 22 25 73 22 20 0a 20 25 73 20 22 25 73 22 20 67 6f 74 6f } //1
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //1 Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
		$a_02_2 = {0f 84 85 00 00 00 90 09 22 00 90 02 04 68 80 00 00 00 6a 02 53 53 90 01 03 40 00 68 00 00 00 40 90 01 01 ff 15 90 01 02 40 00 90 00 } //1
		$a_00_3 = {43 68 61 72 54 6f 4f 65 6d 41 00 } //1
		$a_00_4 = {43 6f 49 6e 69 74 69 61 6c 69 7a 65 00 } //1
		$a_00_5 = {4d 6f 76 65 46 69 6c 65 45 78 41 00 } //1 潍敶楆敬硅A
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}