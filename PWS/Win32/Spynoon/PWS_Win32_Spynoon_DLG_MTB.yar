
rule PWS_Win32_Spynoon_DLG_MTB{
	meta:
		description = "PWS:Win32/Spynoon.DLG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {8b 13 89 42 01 8b 03 8b 16 89 50 05 8b 03 89 06 83 03 0d 8b 03 2b 45 f8 3d fc 0f 00 00 } //1
		$a_81_1 = {47 65 74 4b 65 79 62 6f 61 72 64 54 79 70 65 } //1 GetKeyboardType
		$a_81_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_81_3 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //1 UnhookWindowsHookEx
		$a_81_4 = {45 41 63 74 6e 4c 69 73 74 } //1 EActnList
		$a_81_5 = {57 57 69 6e 53 70 6f 6f 6c } //1 WWinSpool
		$a_81_6 = {65 2d 6d 61 69 6c 20 69 67 5f 7a 75 62 40 75 6b 72 2e 6e 65 74 } //1 e-mail ig_zub@ukr.net
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}