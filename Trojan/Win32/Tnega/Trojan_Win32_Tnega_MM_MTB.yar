
rule Trojan_Win32_Tnega_MM_MTB{
	meta:
		description = "Trojan:Win32/Tnega.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {54 6f 70 31 4d 75 2e 4e 65 74 } //1 Top1Mu.Net
		$a_81_1 = {44 61 74 61 2f 4c 6f 67 6f 2f 53 79 73 74 65 6d 2e 70 72 6f } //1 Data/Logo/System.pro
		$a_81_2 = {72 75 6e 61 73 } //1 runas
		$a_81_3 = {56 69 72 75 73 20 57 6f 72 6b 69 6e 67 } //1 Virus Working
		$a_81_4 = {52 65 6c 65 61 73 65 5c 4d 61 69 6e 2e 70 64 62 } //1 Release\Main.pdb
		$a_81_5 = {5f 63 72 74 5f 64 65 62 75 67 67 65 72 5f 68 6f 6f 6b } //1 _crt_debugger_hook
		$a_81_6 = {4e 74 52 65 73 75 6d 65 50 72 6f 63 65 73 73 } //1 NtResumeProcess
		$a_81_7 = {4f 68 54 54 69 6a 35 6c 6d 6e 6f 6d 6c 6b 6a 73 74 5c 58 75 68 } //1 OhTTij5lmnomlkjst\Xuh
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}