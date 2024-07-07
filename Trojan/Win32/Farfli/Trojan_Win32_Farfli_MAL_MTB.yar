
rule Trojan_Win32_Farfli_MAL_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {43 63 4d 61 69 6e 44 6c 6c 2e 64 6c 6c } //1 CcMainDll.dll
		$a_01_1 = {46 69 72 73 74 52 75 6e } //1 FirstRun
		$a_01_2 = {4d 61 69 6e 52 75 6e } //1 MainRun
		$a_01_3 = {53 65 72 76 69 63 65 4d 61 69 6e } //1 ServiceMain
		$a_01_4 = {54 65 73 74 46 75 6e } //1 TestFun
		$a_01_5 = {53 6c 65 65 70 } //1 Sleep
		$a_01_6 = {43 63 52 6d 74 20 55 70 64 61 74 65 } //1 CcRmt Update
		$a_01_7 = {4e 6f 20 41 63 63 65 73 73 } //1 No Access
		$a_01_8 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //1 ResumeThread
		$a_01_9 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}