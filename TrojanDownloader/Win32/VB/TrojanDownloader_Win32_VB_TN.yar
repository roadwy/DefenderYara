
rule TrojanDownloader_Win32_VB_TN{
	meta:
		description = "TrojanDownloader:Win32/VB.TN,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 74 20 3d 20 46 61 6c 44 6f 77 6e 6c 6f 61 64 65 72 } //1 at = FalDownloader
		$a_01_1 = {73 00 6e 00 73 00 73 00 2e 00 65 00 78 00 65 00 } //1 snss.exe
		$a_01_2 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 6d 00 79 00 2e 00 76 00 62 00 73 00 } //1 cmd.exe /c my.vbs
		$a_01_3 = {77 73 2e 72 75 6e 20 22 63 6d 64 20 2f 63 20 77 6c 6e 69 6f 67 69 6e 2e 65 78 65 22 2c 30 2c 46 61 6c 73 65 20 } //1 ws.run "cmd /c wlniogin.exe",0,False 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}