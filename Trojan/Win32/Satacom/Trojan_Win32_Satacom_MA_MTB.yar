
rule Trojan_Win32_Satacom_MA_MTB{
	meta:
		description = "Trojan:Win32/Satacom.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {66 6f 72 6b 31 30 2e 64 6c 6c } //10 fork10.dll
		$a_01_1 = {57 72 69 74 65 46 69 6c 65 } //1 WriteFile
		$a_01_2 = {53 65 74 54 68 72 65 61 64 50 72 69 6f 72 69 74 79 } //1 SetThreadPriority
		$a_01_3 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 36 34 } //1 GetTickCount64
		$a_01_4 = {43 72 65 61 74 65 45 76 65 6e 74 41 } //1 CreateEventA
		$a_01_5 = {4f 70 65 6e 54 68 72 65 61 64 } //1 OpenThread
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}