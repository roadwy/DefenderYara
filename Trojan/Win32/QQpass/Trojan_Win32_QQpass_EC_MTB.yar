
rule Trojan_Win32_QQpass_EC_MTB{
	meta:
		description = "Trojan:Win32/QQpass.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {4a 4b 4a 54 72 57 47 71 32 33 61 7a 57 53 44 5a 77 36 37 71 } //1 JKJTrWGq23azWSDZw67q
		$a_81_1 = {4b 4c 4a 45 57 45 52 48 73 64 77 71 65 68 32 33 32 31 31 21 40 61 73 64 71 53 41 44 77 65 } //1 KLJEWERHsdwqeh23211!@asdqSADwe
		$a_81_2 = {42 52 45 53 55 5a 43 44 59 2e 6a 70 67 } //1 BRESUZCDY.jpg
		$a_81_3 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
		$a_81_4 = {6f 6e 6c 69 6e 65 2e 64 65 2f 68 6f 6d 65 2f 4f 6c 6c 79 64 62 67 } //1 online.de/home/Ollydbg
		$a_81_5 = {43 72 65 61 74 65 54 68 72 65 61 64 } //1 CreateThread
		$a_81_6 = {4e 74 52 65 73 75 6d 65 50 72 6f 63 65 73 73 } //1 NtResumeProcess
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}