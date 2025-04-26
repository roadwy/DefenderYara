
rule Backdoor_Win32_Bifrose_IC{
	meta:
		description = "Backdoor:Win32/Bifrose.IC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {43 3a 5c 77 61 6d 70 5c 77 77 77 5c [0-20] 5c 53 74 75 62 5c 52 65 6c 65 61 73 65 5c 73 74 75 62 2e 70 64 62 } //1
		$a_00_1 = {b8 4d 5a 00 00 66 39 01 74 04 33 c0 c9 c3 8b 41 3c 03 c1 81 38 50 45 00 00 75 ef 83 65 fc 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}