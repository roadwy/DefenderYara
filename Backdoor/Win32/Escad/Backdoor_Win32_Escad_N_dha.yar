
rule Backdoor_Win32_Escad_N_dha{
	meta:
		description = "Backdoor:Win32/Escad.N!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {32 a2 df 2d 99 2b 00 00 } //1
		$a_03_1 = {0f b6 04 13 41 ff c0 48 ff c2 34 ?? 88 42 ff 41 8b c0 48 3b c1 72 e9 } //1
		$a_01_2 = {0f b6 03 3c 2e 74 09 3c 20 74 05 88 07 48 ff c7 48 ff c3 80 3b 00 75 e8 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Backdoor_Win32_Escad_N_dha_2{
	meta:
		description = "Backdoor:Win32/Escad.N!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {32 a2 df 2d 99 2b 00 00 } //1
		$a_03_1 = {0f b6 04 13 41 ff c0 48 ff c2 34 ?? 88 42 ff 41 8b c0 48 3b c1 72 e9 } //1
		$a_01_2 = {0f b6 03 3c 2e 74 09 3c 20 74 05 88 07 48 ff c7 48 ff c3 80 3b 00 75 e8 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}