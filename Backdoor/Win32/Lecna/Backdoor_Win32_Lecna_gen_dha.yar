
rule Backdoor_Win32_Lecna_gen_dha{
	meta:
		description = "Backdoor:Win32/Lecna.gen!dha,SIGNATURE_TYPE_PEHSTR_EXT,36 00 35 00 0b 00 00 "
		
	strings :
		$a_01_0 = {53 65 54 61 6b 65 4f 77 6e 65 72 73 68 69 70 50 72 69 76 69 6c 65 67 65 } //10 SeTakeOwnershipPrivilege
		$a_01_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //10 CreateToolhelp32Snapshot
		$a_00_2 = {53 65 74 45 6e 74 72 69 65 73 49 6e 41 63 6c 41 } //10 SetEntriesInAclA
		$a_01_3 = {49 6e 74 65 72 6e 65 74 20 45 78 70 31 6f 72 65 72 } //5 Internet Exp1orer
		$a_01_4 = {2f 62 61 6b 2e 68 74 6d } //3 /bak.htm
		$a_01_5 = {41 53 44 46 47 48 } //1 ASDFGH
		$a_01_6 = {2f 64 69 7a 68 69 2e 67 69 66 } //3 /dizhi.gif
		$a_01_7 = {2f 63 6f 6e 6e 65 63 74 2e 67 69 66 } //3 /connect.gif
		$a_01_8 = {5c 6e 65 74 73 76 63 2e 65 78 65 } //3 \netsvc.exe
		$a_01_9 = {5c 6e 65 74 73 63 76 2e 65 78 65 } //3 \netscv.exe
		$a_01_10 = {5c 6e 65 74 73 76 63 73 2e 65 78 65 } //3 \netsvcs.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_00_2  & 1)*10+(#a_01_3  & 1)*5+(#a_01_4  & 1)*3+(#a_01_5  & 1)*1+(#a_01_6  & 1)*3+(#a_01_7  & 1)*3+(#a_01_8  & 1)*3+(#a_01_9  & 1)*3+(#a_01_10  & 1)*3) >=53
 
}