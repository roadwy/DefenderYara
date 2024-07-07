
rule TrojanSpy_Win32_Pavica_PAEC_MTB{
	meta:
		description = "TrojanSpy:Win32/Pavica.PAEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 63 20 72 65 6e 20 22 25 73 2a 2e 2a 22 20 2a 2e 2a 2e 25 6c 75 2e 62 61 6b } //1 /c ren "%s*.*" *.*.%lu.bak
		$a_01_1 = {70 69 6e 67 20 31 2e 31 2e 31 2e 31 20 2d 6e 20 25 75 20 26 20 72 6d 64 69 72 20 22 25 73 22 20 2f 71 20 2f 73 } //1 ping 1.1.1.1 -n %u & rmdir "%s" /q /s
		$a_01_2 = {63 6d 64 2e 65 78 65 } //1 cmd.exe
		$a_01_3 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //1 SeShutdownPrivilege
		$a_01_4 = {5c 00 5c 00 2e 00 5c 00 50 00 49 00 50 00 45 00 5c 00 } //1 \\.\PIPE\
		$a_01_5 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 5c 00 55 00 73 00 6f 00 72 00 69 00 73 00 5c 00 5c 00 42 00 61 00 63 00 6b 00 75 00 70 00 } //1 SOFTWARE\\Usoris\\Backup
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}