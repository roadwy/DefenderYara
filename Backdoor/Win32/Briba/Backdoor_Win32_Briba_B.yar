
rule Backdoor_Win32_Briba_B{
	meta:
		description = "Backdoor:Win32/Briba.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 22 39 33 3b 3b 64 65 79 32 2f 32 77 75 72 24 75 7b } //1 %"93;;dey2/2wur$u{
		$a_01_1 = {72 61 7a 6f 72 5f 2e 64 6c 6c 00 73 74 61 72 74 00 } //1
		$a_00_2 = {00 63 30 64 30 73 6f 30 00 } //1
		$a_01_3 = {80 3e 47 75 0c 80 7e 01 49 75 06 80 7e 02 46 74 07 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}