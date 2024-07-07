
rule Trojan_Win32_Qakbot_QE_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.QE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //3 CallNextHookEx
		$a_81_1 = {47 65 74 46 69 6c 65 56 65 72 73 69 6f 6e 49 6e 66 6f 53 69 7a 65 41 } //3 GetFileVersionInfoSizeA
		$a_81_2 = {4c 6f 63 6b 52 65 73 6f 75 72 63 65 } //3 LockResource
		$a_81_3 = {53 79 73 52 65 41 6c 6c 6f 63 53 74 72 69 6e 67 4c 65 6e } //3 SysReAllocStringLen
		$a_81_4 = {41 63 74 69 76 61 74 65 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 } //3 ActivateKeyboardLayout
		$a_81_5 = {57 69 6e 53 70 6f 6f 6c } //3 WinSpool
		$a_81_6 = {43 4c 6c 65 57 4b 69 72 40 52 45 75 40 67 61 42 4d 67 6d } //3 CLleWKir@REu@gaBMgm
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}