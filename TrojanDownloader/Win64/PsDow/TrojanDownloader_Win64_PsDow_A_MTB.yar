
rule TrojanDownloader_Win64_PsDow_A_MTB{
	meta:
		description = "TrojanDownloader:Win64/PsDow.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e 20 28 6e 65 77 2d 6f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 25 73 27 2c 20 27 25 73 27 29 3b 25 73 } //2 cmd /c powershell.exe -windowstyle hidden (new-object System.Net.WebClient).DownloadFile('%s', '%s');%s
		$a_01_1 = {63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 25 73 20 25 73 26 26 25 73 } //2 cmd /c certutil.exe -urlcache -split -f %s %s&&%s
		$a_01_2 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 61 64 6f 64 62 2e 73 74 72 65 61 6d 22 29 3a 73 65 74 20 77 65 62 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 6d 69 63 72 6f 73 6f 66 74 2e 78 6d 6c 68 74 74 70 22 29 } //2 createobject("adodb.stream"):set web=createobject("microsoft.xmlhttp")
		$a_01_3 = {77 65 62 2e 6f 70 65 6e 20 22 67 65 74 22 2c 2e 61 72 67 75 6d 65 6e 74 73 28 30 29 2c 30 3a 77 65 62 2e 73 65 6e 64 3a 69 66 20 77 65 62 2e 73 74 61 74 75 73 } //2 web.open "get",.arguments(0),0:web.send:if web.status
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}