
rule Trojan_Win32_KillMBR_PAGD_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.PAGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 } //2 \\.\PhysicalDrive
		$a_01_1 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //1 SeShutdownPrivilege
		$a_01_2 = {43 75 73 74 6f 6d 4d 42 52 } //2 CustomMBR
		$a_01_3 = {2d 62 79 70 61 73 73 77 61 72 6e 69 6e 67 } //1 -bypasswarning
		$a_01_4 = {49 66 20 79 6f 75 20 72 75 6e 20 74 68 69 73 20 61 70 70 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 77 69 6c 6c 20 62 65 20 64 65 73 74 72 6f 79 65 64 } //2 If you run this app your computer will be destroyed
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2) >=8
 
}