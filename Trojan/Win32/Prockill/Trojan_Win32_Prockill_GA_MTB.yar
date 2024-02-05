
rule Trojan_Win32_Prockill_GA_MTB{
	meta:
		description = "Trojan:Win32/Prockill.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0e 00 00 01 00 "
		
	strings :
		$a_80_0 = {4b 69 6c 6c 65 72 } //Killer  01 00 
		$a_80_1 = {47 65 74 50 72 6f 63 65 73 73 65 73 } //GetProcesses  01 00 
		$a_80_2 = {74 61 73 6b 6d 67 72 } //taskmgr  01 00 
		$a_80_3 = {72 65 67 65 64 69 74 } //regedit  01 00 
		$a_80_4 = {77 69 72 65 73 68 61 72 6b } //wireshark  01 00 
		$a_80_5 = {76 6d 77 61 72 65 } //vmware  01 00 
		$a_80_6 = {6f 6c 6c 79 64 62 67 } //ollydbg  01 00 
		$a_80_7 = {76 69 72 74 75 61 6c 62 6f 78 } //virtualbox  01 00 
		$a_80_8 = {68 69 6a 61 63 6b 74 68 69 73 } //hijackthis  01 00 
		$a_80_9 = {61 6e 75 62 69 73 } //anubis  01 00 
		$a_80_10 = {6a 6f 65 62 6f 78 } //joebox  01 00 
		$a_80_11 = {6b 65 79 73 63 72 61 6d 62 6c 65 72 } //keyscrambler  01 00 
		$a_80_12 = {6d 73 63 6f 6e 66 69 67 } //msconfig  01 00 
		$a_80_13 = {70 61 6e 64 61 } //panda  00 00 
	condition:
		any of ($a_*)
 
}