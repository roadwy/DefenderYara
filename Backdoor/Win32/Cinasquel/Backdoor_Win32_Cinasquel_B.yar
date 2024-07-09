
rule Backdoor_Win32_Cinasquel_B{
	meta:
		description = "Backdoor:Win32/Cinasquel.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 66 32 33 5f 64 65 69 6e 69 74 } //2 sf23_deinit
		$a_03_1 = {63 3a 5c 57 69 6e 64 6f 77 73 5c 74 65 6d 70 5c [0-10] 2e 65 78 65 } //2
		$a_01_2 = {6d 79 73 71 6c 2e 64 6c 6c 00 73 66 32 33 } //2
		$a_01_3 = {28 25 73 29 20 70 6f 72 74 6e 75 6d 62 65 72 20 28 25 64 29 20 6f 73 76 65 72 73 69 6f 6e 20 28 25 73 29 } //2 (%s) portnumber (%d) osversion (%s)
		$a_03_4 = {5c 63 6e 61 31 32 [0-10] 2e 64 6c 6c } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_03_4  & 1)*2) >=8
 
}