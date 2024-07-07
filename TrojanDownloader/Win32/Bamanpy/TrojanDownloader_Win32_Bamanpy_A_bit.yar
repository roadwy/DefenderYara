
rule TrojanDownloader_Win32_Bamanpy_A_bit{
	meta:
		description = "TrojanDownloader:Win32/Bamanpy.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 00 61 00 73 00 73 00 2e 00 74 00 78 00 74 00 } //1 pass.txt
		$a_81_1 = {6e 65 74 32 66 74 70 2e 72 75 } //1 net2ftp.ru
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {62 00 61 00 64 00 6d 00 61 00 6e 00 70 00 72 00 6f 00 6a 00 65 00 63 00 74 00 40 00 65 00 78 00 2e 00 75 00 61 00 } //1 badmanproject@ex.ua
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}