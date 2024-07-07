
rule Backdoor_Win32_Refpron_A{
	meta:
		description = "Backdoor:Win32/Refpron.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {32 cb 88 4c 10 ff 0f b7 45 f2 8b 55 fc 0f b6 44 02 ff 66 03 45 f0 66 69 c0 6d ce 66 05 bf 58 66 89 45 f0 66 ff 45 f2 66 ff 4d ee } //5
		$a_01_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //2 WriteProcessMemory
		$a_01_2 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //2 CreateRemoteThread
		$a_01_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 64 72 6d 67 73 2e 73 79 73 } //1 C:\WINDOWS\SYSTEM32\drmgs.sys
		$a_01_4 = {70 5f 76 65 72 3a 32 30 30 } //1 p_ver:200
		$a_01_5 = {2e 73 79 73 20 6e 6f 74 20 66 6f 75 6e 64 21 } //1 .sys not found!
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}