
rule Backdoor_Win32_Bifrose_CB_MTB{
	meta:
		description = "Backdoor:Win32/Bifrose.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 74 65 6d 70 5c 76 69 72 75 73 2e 65 78 65 } //1 c:\temp\virus.exe
		$a_01_1 = {74 65 6d 70 32 2e 65 78 65 } //1 temp2.exe
		$a_01_2 = {74 65 6d 70 31 2e 64 6f 63 } //1 temp1.doc
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}