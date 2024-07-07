
rule TrojanDropper_Win32_Delf_EI{
	meta:
		description = "TrojanDropper:Win32/Delf.EI,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 69 6e 64 20 46 69 6c 65 20 73 75 63 63 65 65 64 2e } //4 Bind File succeed.
		$a_01_1 = {46 6e 61 6c 6c 79 20 46 69 6c 65 20 50 61 74 68 20 43 61 6e 20 4e 6f 74 20 45 6d 70 74 79 21 } //4 Fnally File Path Can Not Empty!
		$a_01_2 = {50 72 6f 5f 42 69 6e 64 } //3 Pro_Bind
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*3) >=11
 
}