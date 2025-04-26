
rule Backdoor_Win32_Yohakest_A{
	meta:
		description = "Backdoor:Win32/Yohakest.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 68 61 63 6b 2f 63 6f 6d 6d 61 6e 64 2e 70 68 70 3f 63 6f 6d 70 75 74 65 72 3d 25 73 00 } //1
		$a_00_1 = {5c 79 6f 79 6f 5c 64 6f 63 75 } //1 \yoyo\docu
		$a_01_2 = {48 61 63 6b 65 72 20 73 61 79 73 3a 00 } //1
		$a_01_3 = {33 36 30 30 00 57 69 6e 64 6f 77 73 20 54 61 73 6b 20 4d 61 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}