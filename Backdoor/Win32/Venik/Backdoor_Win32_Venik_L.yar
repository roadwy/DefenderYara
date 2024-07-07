
rule Backdoor_Win32_Venik_L{
	meta:
		description = "Backdoor:Win32/Venik.L,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 44 24 2c 69 c6 44 24 2d 63 c6 44 24 2e 65 c6 44 24 2f 44 c6 44 24 32 00 e8 } //1
		$a_01_1 = {33 36 30 74 72 61 79 2e 65 78 65 00 25 73 36 74 25 2e 33 64 2e 64 6c 6c } //1
		$a_01_2 = {2e 48 4c 2e ff 7b 00 00 63 6d 64 2e 65 78 65 00 2f 63 20 70 69 6e 67 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}