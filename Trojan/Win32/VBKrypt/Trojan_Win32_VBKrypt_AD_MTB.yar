
rule Trojan_Win32_VBKrypt_AD_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {62 45 41 4e 20 62 45 41 4e 20 62 45 41 4e 20 62 45 41 4e } //1 bEAN bEAN bEAN bEAN
		$a_81_1 = {72 65 76 65 67 65 74 61 74 65 64 32 } //1 revegetated2
		$a_81_2 = {73 75 62 64 6f 6c 6f 75 73 6e 65 73 73 } //1 subdolousness
		$a_81_3 = {6e 61 63 68 69 74 6f 63 68 37 } //1 nachitoch7
		$a_81_4 = {73 74 61 67 67 61 72 64 73 33 } //1 staggards3
		$a_81_5 = {48 41 52 54 53 48 4f 52 4e 45 } //1 HARTSHORNE
		$a_81_6 = {4c 61 77 68 61 6e 64 36 } //1 Lawhand6
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule Trojan_Win32_VBKrypt_AD_MTB_2{
	meta:
		description = "Trojan:Win32/VBKrypt.AD!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 61 6d 70 6c 65 20 41 64 64 49 6e 20 50 72 6f 6a 65 63 74 } //1 Sample AddIn Project
		$a_01_1 = {5c 00 53 00 65 00 6c 00 65 00 63 00 74 00 43 00 61 00 73 00 65 00 45 00 6e 00 75 00 6d 00 2e 00 76 00 62 00 70 00 } //1 \SelectCaseEnum.vbp
		$a_01_2 = {75 00 73 00 65 00 73 00 20 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 68 00 6f 00 6f 00 6b 00 73 00 } //1 uses windows hooks
		$a_01_3 = {46 75 6e 63 74 69 6f 6e 20 56 69 72 74 75 61 6c 41 6c 6c 6f 63 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 28 6c 70 41 64 64 72 65 73 73 20 41 73 20 41 6e 79 2c 20 42 79 56 61 6c 20 64 77 53 69 7a 65 } //1 Function VirtualAlloc Lib "kernel32" (lpAddress As Any, ByVal dwSize
		$a_01_4 = {4e 00 74 00 51 00 75 00 65 00 72 00 79 00 49 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //1 NtQueryInformationProcess
		$a_01_5 = {43 00 6c 00 61 00 73 00 73 00 69 00 63 00 20 00 41 00 65 00 72 00 6f 00 70 00 6c 00 61 00 6e 00 65 00 20 00 47 00 61 00 6d 00 65 00 } //1 Classic Aeroplane Game
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}