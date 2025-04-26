
rule Trojan_Win32_Injector_D_MTB{
	meta:
		description = "Trojan:Win32/Injector.D!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {69 6e 66 5c 75 73 62 73 74 6f 72 2e 69 6e 66 } //1 inf\usbstor.inf
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run\
		$a_01_2 = {5c 41 6e 74 69 4f 70 65 6e 50 72 6f 63 65 73 73 2e 64 6c 6c } //1 \AntiOpenProcess.dll
		$a_01_3 = {68 6f 6f 6b 64 6c 6c 2e 64 6c 6c } //1 hookdll.dll
		$a_01_4 = {49 6e 73 74 61 6c 6c 48 6f 6f 6b } //1 InstallHook
		$a_01_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}