
rule Backdoor_Win32_Popwin_gen_H{
	meta:
		description = "Backdoor:Win32/Popwin.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_02_0 = {3d 2b 05 00 00 73 07 b8 e6 73 3e 02 90 09 04 00 8b 45 fc 90 05 01 01 5e } //5
		$a_01_1 = {83 f8 f0 76 0b 33 d2 b9 00 e1 f5 05 f7 f1 8b c2 } //5
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 } //1
	condition:
		((#a_02_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1) >=11
 
}