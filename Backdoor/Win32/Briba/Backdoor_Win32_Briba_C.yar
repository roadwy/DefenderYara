
rule Backdoor_Win32_Briba_C{
	meta:
		description = "Backdoor:Win32/Briba.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {00 75 70 64 61 74 2e 64 6c 6c 00 52 65 70 6f 72 74 45 72 72 6f 72 00 } //1
		$a_01_1 = {00 74 3d 25 73 26 64 3d 25 64 26 6a 73 6f 6e 3d 00 } //1
		$a_01_2 = {00 74 3d 25 73 26 69 64 3d 25 64 26 73 3d 00 } //1
		$a_01_3 = {25 22 39 33 3b 3b 64 65 79 32 2f 32 77 75 72 24 75 7b } //1 %"93;;dey2/2wur$u{
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}