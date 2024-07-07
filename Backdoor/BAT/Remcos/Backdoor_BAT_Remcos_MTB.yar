
rule Backdoor_BAT_Remcos_MTB{
	meta:
		description = "Backdoor:BAT/Remcos!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 6b 62 48 6f 6f 6b } //1 get_kbHook
		$a_01_1 = {67 65 74 5f 55 73 65 72 } //1 get_User
		$a_01_2 = {67 65 74 5f 50 61 73 73 77 6f 72 64 } //1 get_Password
		$a_01_3 = {67 65 74 5f 54 6f 74 61 6c 50 68 79 73 69 63 61 6c 4d 65 6d 6f 72 79 } //1 get_TotalPhysicalMemory
		$a_01_4 = {67 65 74 5f 50 72 6f 63 65 73 73 4e 61 6d 65 } //1 get_ProcessName
		$a_01_5 = {67 65 74 5f 41 74 74 61 63 68 6d 65 6e 74 73 } //1 get_Attachments
		$a_01_6 = {67 65 74 5f 43 74 72 6c 4b 65 79 44 6f 77 6e } //1 get_CtrlKeyDown
		$a_01_7 = {67 65 74 5f 41 6c 74 4b 65 79 44 6f 77 6e } //1 get_AltKeyDown
		$a_01_8 = {67 65 74 5f 43 61 70 73 4c 6f 63 6b } //1 get_CapsLock
		$a_01_9 = {67 65 74 5f 53 68 69 66 74 4b 65 79 44 6f 77 6e } //1 get_ShiftKeyDown
		$a_01_10 = {73 65 74 5f 6b 62 48 6f 6f 6b } //1 set_kbHook
		$a_01_11 = {73 65 74 5f 43 72 65 64 65 6e 74 69 61 6c 73 } //1 set_Credentials
		$a_01_12 = {73 65 74 5f 43 72 65 61 74 65 4e 6f 57 69 6e 64 6f 77 } //1 set_CreateNoWindow
		$a_01_13 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 set_UseShellExecute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=14
 
}