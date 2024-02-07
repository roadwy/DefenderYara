
rule Ransom_Win32_Tyrozim_A{
	meta:
		description = "Ransom:Win32/Tyrozim.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5a 3a 5c 53 68 61 64 6f 77 5c 53 69 6c 65 6e 74 53 70 72 69 6e 67 5c 52 65 6c 65 61 73 65 5c 24 5f 31 2e 70 64 62 } //01 00  Z:\Shadow\SilentSpring\Release\$_1.pdb
		$a_01_1 = {0f a2 89 c7 31 c0 81 fb 47 65 6e 75 0f 95 c0 89 c5 81 fa 69 6e 65 49 0f 95 c0 09 c5 81 f9 6e 74 65 6c 0f 95 c0 09 c5 0f 84 } //01 00 
		$a_01_2 = {81 fb 41 75 74 68 0f 95 c0 89 c6 81 fa 65 6e 74 69 0f 95 c0 09 c6 81 f9 63 41 4d 44 0f 95 c0 09 c6 0f 85 } //00 00 
	condition:
		any of ($a_*)
 
}