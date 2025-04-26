
rule TrojanDownloader_Win32_Banload_ZEK{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZEK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 6c 6f 72 65 6e 63 65 63 68 65 6e 2e 63 6f 6d 2f 63 73 73 2f 73 63 72 65 65 6e 2f 73 79 73 2f 64 65 66 61 75 6c 74 2e 6a 70 67 } //1 florencechen.com/css/screen/sys/default.jpg
		$a_01_1 = {43 3a 5c 54 45 4d 50 5c 77 69 6e 6c 6f 67 69 6e 2e 65 78 65 } //1 C:\TEMP\winlogin.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}