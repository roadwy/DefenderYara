
rule Backdoor_Win32_Farfli_AM_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {42 61 69 64 75 41 6c 6c 53 6f 66 74 } //BaiduAllSoft  3
		$a_80_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //URLDownloadToFileA  3
		$a_80_2 = {75 73 65 72 73 2e 71 7a 6f 6e 65 2e 71 71 2e 63 6f 6d } //users.qzone.qq.com  3
		$a_80_3 = {63 67 69 5f 67 65 74 5f 70 6f 72 74 72 61 69 74 2e 66 63 67 } //cgi_get_portrait.fcg  3
		$a_80_4 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 62 6c 61 63 6b 63 61 74 31 2e 6c 6f 67 } //c:\windows\blackcat1.log  3
		$a_80_5 = {48 65 6c 6c 6f 20 57 6f 72 6c 64 21 } //Hello World!  3
		$a_80_6 = {43 3a 5c 49 4e 54 45 52 4e 41 4c 5c 52 45 4d 4f 54 45 2e 45 58 45 } //C:\INTERNAL\REMOTE.EXE  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}