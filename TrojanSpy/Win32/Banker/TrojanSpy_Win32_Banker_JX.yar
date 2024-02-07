
rule TrojanSpy_Win32_Banker_JX{
	meta:
		description = "TrojanSpy:Win32/Banker.JX,SIGNATURE_TYPE_PEHSTR,1f 00 1f 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 63 6f 6e 66 69 67 65 78 2e 64 6c 6c 00 00 } //0a 00 
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //0a 00  URLDownloadToFileA
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {61 72 71 75 69 76 6f 75 70 67 72 61 64 65 72 2e 73 35 2e 63 6f 6d } //01 00  arquivoupgrader.s5.com
		$a_01_4 = {41 75 74 65 6e 74 69 63 61 63 61 6f 48 6f 74 6d 61 69 6c } //00 00  AutenticacaoHotmail
	condition:
		any of ($a_*)
 
}