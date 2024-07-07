
rule Backdoor_Win32_Talsab_G{
	meta:
		description = "Backdoor:Win32/Talsab.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {00 66 64 77 61 71 65 36 32 33 00 } //1
		$a_01_1 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed } //1
		$a_00_2 = {00 6e 74 6c 64 72 2e 64 6c 6c 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}