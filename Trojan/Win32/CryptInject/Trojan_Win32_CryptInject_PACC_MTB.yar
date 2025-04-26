
rule Trojan_Win32_CryptInject_PACC_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PACC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 43 6f 64 65 49 6e 6a 65 63 74 69 6f 6e 2e 70 64 62 } //1 ShellCodeInjection.pdb
		$a_01_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 43 00 20 00 70 00 69 00 6e 00 67 00 20 00 31 00 2e 00 31 00 2e 00 31 00 2e 00 31 00 20 00 2d 00 6e 00 20 00 31 00 20 00 2d 00 77 00 20 00 33 00 30 00 30 00 30 00 20 00 3e 00 20 00 4e 00 75 00 6c 00 20 00 26 00 20 00 44 00 65 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 71 00 20 00 22 00 25 00 73 00 22 00 } //1 cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q "%s"
		$a_01_2 = {2f 68 6f 6f 6b 69 6e 67 72 65 73 75 6c 74 73 } //1 /hookingresults
		$a_01_3 = {47 6f 74 20 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 Got VirtualAllocEx
		$a_01_4 = {47 6f 74 20 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 Got WriteProcessMemory
		$a_01_5 = {47 6f 74 20 43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 Got CreateRemoteThread
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}