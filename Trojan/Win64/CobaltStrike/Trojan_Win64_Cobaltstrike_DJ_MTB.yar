
rule Trojan_Win64_Cobaltstrike_DJ_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_81_1 = {65 72 74 66 67 79 68 66 72 68 73 64 73 6a } //1 ertfgyhfrhsdsj
		$a_81_2 = {68 67 68 6a 66 75 69 67 73 79 67 64 68 78 73 6b 65 72 79 66 68 } //1 hghjfuigsygdhxskeryfh
		$a_81_3 = {6a 68 68 66 67 68 66 68 67 66 66 } //1 jhhfghfhgff
		$a_81_4 = {6b 66 67 73 72 73 72 74 66 6b 64 68 73 72 65 79 6b } //1 kfgsrsrtfkdhsreyk
		$a_81_5 = {78 66 47 61 64 73 67 65 75 66 68 72 6b } //1 xfGadsgeufhrk
		$a_81_6 = {4e 6f 52 65 6d 6f 76 65 } //1 NoRemove
		$a_81_7 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_8 = {43 6c 69 65 6e 74 54 6f 53 63 72 65 65 6e } //1 ClientToScreen
		$a_81_9 = {4d 73 54 65 67 2e 64 6c 6c } //1 MsTeg.dll
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}