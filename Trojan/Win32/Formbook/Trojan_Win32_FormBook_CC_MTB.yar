
rule Trojan_Win32_FormBook_CC_MTB{
	meta:
		description = "Trojan:Win32/FormBook.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {57 41 5f 56 4d 53 49 42 } //03 00  WA_VMSIB
		$a_81_1 = {44 6f 6e 20 48 4f 20 64 6f 6e } //03 00  Don HO don
		$a_81_2 = {4c 65 78 78 40 62 61 6b 6c 61 6e 6f 76 2e 6e 65 74 } //03 00  Lexx@baklanov.net
		$a_81_3 = {55 6e 61 62 6c 65 20 74 6f 20 6b 69 6c 6c 20 70 72 6f 63 65 73 73 } //03 00  Unable to kill process
		$a_81_4 = {53 65 6c 65 63 74 20 61 20 70 72 6f 63 65 73 73 20 74 6f 20 62 65 20 6b 69 6c 6c 65 64 } //03 00  Select a process to be killed
		$a_81_5 = {53 79 73 49 6e 66 6f 20 76 32 2e 30 20 62 65 74 61 } //03 00  SysInfo v2.0 beta
		$a_81_6 = {43 6f 54 61 73 6b 4d 65 6d 41 6c 6c 6f 63 } //00 00  CoTaskMemAlloc
	condition:
		any of ($a_*)
 
}