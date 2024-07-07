
rule Backdoor_Win32_Popwin_gen_D{
	meta:
		description = "Backdoor:Win32/Popwin.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {64 65 6c 20 25 30 0d 0a 00 00 00 00 22 20 67 6f 74 6f 20 73 65 6c 66 6b 69 6c 6c 0d 0a 00 00 00 69 66 20 65 78 69 73 74 20 22 00 00 } //1
		$a_03_1 = {6a 01 68 b8 0b 00 00 8d 85 90 01 02 ff ff 68 90 01 04 50 be 90 01 04 53 56 e8 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}