
rule Trojan_Win32_Vinor_A{
	meta:
		description = "Trojan:Win32/Vinor.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 6f 64 47 65 74 48 50 72 6f 63 45 78 65 } //3 modGetHProcExe
		$a_01_1 = {68 56 72 54 72 61 79 63 68 6b } //3 hVrTraychk
		$a_01_2 = {57 00 69 00 6e 00 48 00 74 00 74 00 70 00 2e 00 57 00 69 00 6e 00 48 00 74 00 74 00 70 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 2e 00 35 00 2e 00 31 00 } //1 WinHttp.WinHttpRequest.5.1
		$a_00_3 = {61 00 76 00 70 00 2e 00 65 00 78 00 65 00 } //1 avp.exe
		$a_01_4 = {62 00 6c 00 6f 00 67 00 2e 00 6e 00 61 00 76 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 2f 00 50 00 6f 00 73 00 74 00 56 00 69 00 65 00 77 00 2e 00 6e 00 68 00 6e 00 } //1 blog.naver.com/PostView.nhn
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}