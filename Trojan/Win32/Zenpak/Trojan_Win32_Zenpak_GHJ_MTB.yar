
rule Trojan_Win32_Zenpak_GHJ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {c6 45 e0 61 c6 45 e1 6d c6 45 e2 44 c6 45 e3 61 c6 45 e4 74 c6 45 e5 61 c6 45 e6 5c c6 45 e7 77 c6 45 e8 69 c6 45 e9 6e c6 45 ea 6e c6 45 eb 74 c6 45 ec 5c c6 45 ed 6d c6 45 ee 75 c6 45 ef 73 c6 45 f0 69 c6 45 f1 63 c6 45 f2 2e c6 45 f3 65 c6 45 f4 78 c6 45 f5 65 } //10
		$a_01_1 = {63 6d 64 20 2f 63 20 73 74 61 72 74 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 31 31 34 35 31 34 } //1 cmd /c start C:\ProgramData\114514
		$a_01_2 = {63 6d 64 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 74 20 2f 69 6d 20 6d 6d 63 2e 65 78 65 } //1 cmd /c taskkill /f /t /im mmc.exe
		$a_80_3 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 31 31 34 35 31 34 } //C:\ProgramData\114514  1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1) >=13
 
}