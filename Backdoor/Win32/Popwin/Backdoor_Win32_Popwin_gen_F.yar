
rule Backdoor_Win32_Popwin_gen_F{
	meta:
		description = "Backdoor:Win32/Popwin.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 3d 2b 05 00 00 73 07 b8 e6 73 3e 02 } //5
		$a_01_1 = {83 f8 f0 76 0b 33 d2 b9 00 e1 f5 05 f7 f1 8b c2 } //5
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 } //1
		$a_00_3 = {77 69 6e 6c 6f 67 6f 6e 2e 65 78 65 00 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=12
 
}