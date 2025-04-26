
rule Backdoor_Win32_IPRS{
	meta:
		description = "Backdoor:Win32/IPRS,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 70 72 6f 67 72 61 7e 31 5c 69 6e 74 65 72 6e 7e 31 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 20 } //3 c:\progra~1\intern~1\iexplore.exe 
		$a_01_1 = {6f 70 65 6e 00 68 74 74 70 3a 2f 2f 36 34 2e 31 35 36 2e 33 31 2e } //3 灯湥栀瑴㩰⼯㐶ㄮ㘵㌮⸱
		$a_01_2 = {6f 70 65 6e 00 68 74 74 70 3a 2f 2f 77 77 77 } //2
		$a_01_3 = {45 4e 54 45 52 00 70 72 65 6d 69 75 6d } //4
		$a_02_4 = {70 72 65 6d 69 75 6d ?? 47 44 ?? 00 40 49 50 52 53 31 30 31 00 } //4
		$a_01_5 = {54 68 69 73 20 63 61 6c 6c 20 69 73 20 6e 6f 74 20 66 72 65 65 2c 20 74 68 69 73 20 63 61 6c 6c 20 69 6e 76 6f 6c 76 65 73 20 64 69 61 6c 69 6e 67 } //2 This call is not free, this call involves dialing
		$a_01_6 = {61 20 70 72 65 6d 69 75 6d 20 72 61 74 65 20 6e 75 6d 62 65 72 2c 20 } //2 a premium rate number, 
		$a_01_7 = {52 61 73 45 6e 75 6d 43 6f 6e 6e 65 63 74 69 6f 6e 73 41 } //3 RasEnumConnectionsA
		$a_01_8 = {2e 63 6f 6d 2f 6d 65 6d 62 65 72 73 } //2 .com/members
		$a_01_9 = {2e 6e 65 74 2f 6d 65 6d 62 65 72 73 } //2 .net/members
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*4+(#a_02_4  & 1)*4+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*3+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2) >=10
 
}