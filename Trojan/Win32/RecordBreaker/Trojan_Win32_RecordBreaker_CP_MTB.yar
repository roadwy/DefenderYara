
rule Trojan_Win32_RecordBreaker_CP_MTB{
	meta:
		description = "Trojan:Win32/RecordBreaker.CP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_81_0 = {53 65 74 44 72 76 } //1 SetDrv
		$a_81_1 = {53 70 65 63 69 61 6c 42 75 69 6c 64 } //1 SpecialBuild
		$a_81_2 = {37 7a 20 53 46 58 20 43 6f 6e 73 74 72 75 63 74 6f 72 20 76 34 2e 36 2e 30 2e 30 20 28 68 74 74 70 3a 2f 2f 75 73 62 74 6f 72 2e 72 75 2f 76 69 65 77 74 6f 70 69 63 2e 70 68 70 3f 74 3d 37 39 38 29 } //1 7z SFX Constructor v4.6.0.0 (http://usbtor.ru/viewtopic.php?t=798)
		$a_81_3 = {35 79 77 36 34 75 65 35 6a 79 74 75 72 79 67 } //1 5yw64ue5jyturyg
		$a_81_4 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_81_5 = {54 68 72 65 61 64 33 32 4e 65 78 74 } //1 Thread32Next
		$a_81_6 = {4f 70 65 6e 54 68 72 65 61 64 } //1 OpenThread
		$a_81_7 = {53 75 73 70 65 6e 64 54 68 72 65 61 64 } //1 SuspendThread
		$a_81_8 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=8
 
}