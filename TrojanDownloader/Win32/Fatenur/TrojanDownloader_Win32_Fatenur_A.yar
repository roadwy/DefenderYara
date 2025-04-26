
rule TrojanDownloader_Win32_Fatenur_A{
	meta:
		description = "TrojanDownloader:Win32/Fatenur.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {66 74 70 2e 6f 6e 2e 75 66 61 6e 65 74 2e 72 75 3e 3e 25 73 79 73 74 65 6d 72 6f 6f 74 25 2f 66 66 2e 62 61 74 } //4 ftp.on.ufanet.ru>>%systemroot%/ff.bat
		$a_01_1 = {43 3a 2f 69 73 65 6e 64 73 6d 73 5f 73 65 74 75 70 2e 65 78 65 } //1 C:/isendsms_setup.exe
		$a_01_2 = {61 74 74 72 69 62 20 2b 68 20 25 73 79 73 74 65 6d 72 6f 6f 74 25 2f 74 61 73 6b 73 2f 2a 2e 2a } //1 attrib +h %systemroot%/tasks/*.*
		$a_01_3 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 73 65 74 20 63 75 72 72 65 6e 74 70 72 6f 66 69 6c 65 20 73 74 61 74 65 20 6f 66 66 } //1 netsh advfirewall set currentprofile state off
		$a_01_4 = {73 63 20 63 6f 6e 66 69 67 20 77 73 63 73 76 63 20 73 74 61 72 74 3d 20 64 69 73 61 62 6c 65 64 } //1 sc config wscsvc start= disabled
		$a_01_5 = {73 63 20 73 74 61 72 74 20 73 63 68 65 64 75 6c 65 } //1 sc start schedule
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}