
rule Trojan_Win32_Farfli_LMF_MTB{
	meta:
		description = "Trojan:Win32/Farfli.LMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,24 00 24 00 0b 00 00 "
		
	strings :
		$a_81_0 = {25 34 64 2e 25 32 64 2e 25 32 64 2d 25 32 64 3a 25 32 64 3a 25 32 64 } //1 %4d.%2d.%2d-%2d:%2d:%2d
		$a_81_1 = {5c 44 69 73 70 6c 61 79 53 65 73 73 69 6f 6e 43 6f 6e 74 61 69 6e 65 72 73 2e 6c 6f 67 } //2 \DisplaySessionContainers.log
		$a_81_2 = {5c 53 65 73 73 69 6f 6e 43 6f 6e 74 61 69 6e 65 72 73 2e 6c 6f 67 } //2 \SessionContainers.log
		$a_81_3 = {75 6e 61 62 6c 65 20 74 6f 20 63 6f 6e 6e 65 63 74 20 74 6f 20 25 73 3a 25 73 } //3 unable to connect to %s:%s
		$a_81_4 = {63 6f 6e 6e 65 63 74 69 6f 6e 20 61 62 6f 72 74 65 64 } //3 connection aborted
		$a_81_5 = {73 75 63 63 65 65 64 20 74 6f 20 63 6f 6e 6e 65 63 74 20 74 6f 20 25 73 3a 25 73 } //4 succeed to connect to %s:%s
		$a_81_6 = {63 6f 6e 6e 65 63 74 69 6f 6e 20 61 6c 72 65 61 64 79 20 69 6e 20 70 72 6f 67 72 65 73 73 } //4 connection already in progress
		$a_81_7 = {4d 53 49 45 20 36 2e 30 } //5 MSIE 6.0
		$a_81_8 = {43 6f 6e 73 6f 6c 65 } //6 Console
		$a_81_9 = {57 69 6e 53 74 61 30 5c 44 65 66 61 75 6c 74 } //7 WinSta0\Default
		$a_81_10 = {6f 6e 6c 79 6c 6f 61 64 69 6e 6d 79 73 65 6c 66 } //8 onlyloadinmyself
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*4+(#a_81_6  & 1)*4+(#a_81_7  & 1)*5+(#a_81_8  & 1)*6+(#a_81_9  & 1)*7+(#a_81_10  & 1)*8) >=36
 
}