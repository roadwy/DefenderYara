
rule Trojan_Win32_WebShell_Y{
	meta:
		description = "Trojan:Win32/WebShell.Y,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 61 67 65 5f 4c 6f 61 64 } //1 Page_Load
		$a_01_1 = {50 4f 53 54 46 69 6c 65 55 70 6c 6f 61 64 } //1 POSTFileUpload
		$a_01_2 = {50 4f 53 54 46 69 6c 65 44 6f 77 6e 6c 6f 61 64 } //1 POSTFileDownload
		$a_01_3 = {50 4f 53 54 46 69 6c 65 44 65 6c 65 74 65 } //1 POSTFileDelete
		$a_01_4 = {50 4f 53 54 43 6d 64 45 78 65 63 75 74 65 } //1 POSTCmdExecute
		$a_01_5 = {2f 00 63 00 6f 00 6e 00 74 00 61 00 63 00 74 00 2e 00 61 00 73 00 70 00 78 00 } //1 /contact.aspx
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}