
rule Trojan_Win32_FlyStudio_MA_MTB{
	meta:
		description = "Trojan:Win32/FlyStudio.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {74 78 74 2e 7a 69 62 6f 73 68 75 6f 7a 75 61 6e 2e 63 6f 6d 2f 64 78 64 } //1 txt.ziboshuozuan.com/dxd
		$a_81_1 = {78 69 61 7a 61 69 62 61 2e 63 6f 6d 2f 68 74 6d 6c 2f } //1 xiazaiba.com/html/
		$a_81_2 = {57 69 6e 48 74 74 70 2e 57 69 6e 48 74 74 70 52 65 71 75 65 73 74 2e 35 2e 31 } //1 WinHttp.WinHttpRequest.5.1
		$a_81_3 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 } //1 Content-Type: application/x-www-form-urlencoded
		$a_81_4 = {63 6d 64 2e 65 78 65 20 2f 63 20 64 65 6c } //1 cmd.exe /c del
		$a_81_5 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 39 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 29 } //1 Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)
		$a_81_6 = {6d 73 68 74 61 2e 65 78 65 } //1 mshta.exe
		$a_81_7 = {53 65 74 20 57 73 68 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 Set WshShell = CreateObject("WScript.Shell")
		$a_81_8 = {57 73 68 53 68 65 6c 6c 2e 45 78 65 63 } //1 WshShell.Exec
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}