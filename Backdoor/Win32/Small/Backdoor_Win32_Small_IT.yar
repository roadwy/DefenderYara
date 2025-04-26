
rule Backdoor_Win32_Small_IT{
	meta:
		description = "Backdoor:Win32/Small.IT,SIGNATURE_TYPE_PEHSTR_EXT,38 01 38 01 06 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 64 25 30 34 64 } //100 http://%s:%d/%d%04d
		$a_00_1 = {63 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 25 73 } //100 c:\Program Files\Internet Explorer\%s
		$a_02_2 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c ?? 2e 65 78 65 } //100
		$a_00_3 = {4d 65 73 73 65 6e 67 65 72 } //10 Messenger
		$a_00_4 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //1 SeDebugPrivilege
		$a_00_5 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 } //1 AdjustTokenPrivileges
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*100+(#a_02_2  & 1)*100+(#a_00_3  & 1)*10+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=312
 
}