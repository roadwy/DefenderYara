
rule TrojanDownloader_Win32_Hadoock_A_bit{
	meta:
		description = "TrojanDownloader:Win32/Hadoock.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 00 74 00 6d 00 70 00 5c 00 73 00 76 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //2 \tmp\svhost.exe
		$a_00_1 = {5c 00 73 00 76 00 68 00 6f 00 73 00 74 00 2e 00 62 00 61 00 63 00 6b 00 75 00 70 00 } //2 \svhost.backup
		$a_00_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //2 Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_3 = {2f 00 75 00 70 00 64 00 61 00 74 00 65 00 72 00 65 00 73 00 74 00 61 00 72 00 74 00 } //1 /updaterestart
		$a_03_4 = {ba 0b 00 00 00 8b 38 83 c9 ff 89 13 8b 55 dc 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 89 53 04 50 89 45 d0 89 4b 08 8b 4d e4 89 4b 0c ff } //1
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_03_4  & 1)*1) >=6
 
}