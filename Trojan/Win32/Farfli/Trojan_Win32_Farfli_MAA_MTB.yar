
rule Trojan_Win32_Farfli_MAA_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_00_0 = {66 83 fe 01 75 02 33 f6 8a 04 39 8b d6 81 e2 ff ff 00 00 2c 7a 8a 54 54 18 32 d0 46 88 14 39 41 3b cd 7c } //1
		$a_01_1 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //1 GetAsyncKeyState
		$a_01_2 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_3 = {50 72 6f 63 65 73 73 33 32 46 69 72 73 74 } //1 Process32First
		$a_01_4 = {5b 50 61 75 73 65 20 42 72 65 61 6b 5d } //1 [Pause Break]
		$a_01_5 = {5b 50 61 67 65 44 6f 77 6e 5d } //1 [PageDown]
		$a_01_6 = {44 6c 6c 55 70 64 61 74 65 } //1 DllUpdate
		$a_01_7 = {53 65 72 76 69 63 65 4d 61 69 6e } //1 ServiceMain
		$a_01_8 = {55 6e 69 6e 73 74 61 6c 6c } //1 Uninstall
		$a_01_9 = {6d 61 69 6e 64 6c 6c 2e 64 6c 6c } //1 maindll.dll
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}