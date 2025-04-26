
rule Trojan_Win32_FakeFolder_EM_MTB{
	meta:
		description = "Trojan:Win32/FakeFolder.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_81_0 = {78 6c 73 78 22 2c 20 22 73 66 73 6c 66 74 6e 64 79 74 6d 70 2e 65 78 65 22 } //10 xlsx", "sfslftndytmp.exe"
		$a_81_1 = {78 6c 73 78 22 2c 20 22 78 77 69 6b 6a 79 6c 77 67 6c 73 66 2e 65 78 65 22 } //10 xlsx", "xwikjylwglsf.exe"
		$a_81_2 = {78 6c 73 22 2c 20 22 63 71 69 67 72 6d 68 65 6e 77 6e 62 2e 65 78 65 22 } //10 xls", "cqigrmhenwnb.exe"
		$a_81_3 = {44 6c 6c 43 61 6c 6c 28 22 73 68 65 6c 6c 33 32 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 57 } //1 DllCall("shell32\ShellExecuteW
		$a_81_4 = {43 6c 43 6c 69 70 62 6f 61 72 64 } //1 ClClipboard
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=12
 
}