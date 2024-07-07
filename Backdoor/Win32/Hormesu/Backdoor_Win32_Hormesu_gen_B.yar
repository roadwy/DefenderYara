
rule Backdoor_Win32_Hormesu_gen_B{
	meta:
		description = "Backdoor:Win32/Hormesu.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 7d f4 03 7d f8 8a 07 c0 c8 03 34 29 88 07 41 3b ce 89 4d f8 7c e9 } //1
		$a_01_1 = {44 6c 6c 4c 6f 61 64 65 72 2e 64 6c 6c 00 4c 6f 61 64 54 50 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}