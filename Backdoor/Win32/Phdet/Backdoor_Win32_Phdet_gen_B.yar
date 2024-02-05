
rule Backdoor_Win32_Phdet_gen_B{
	meta:
		description = "Backdoor:Win32/Phdet.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 30 ef 02 98 33 f6 33 db 56 43 53 e8 90 01 04 68 04 01 00 00 90 00 } //01 00 
		$a_03_1 = {68 2f e0 1d aa 56 53 c7 85 90 01 04 01 00 01 00 90 00 } //01 00 
		$a_03_2 = {74 14 53 57 6a 02 e8 90 01 04 ff 35 90 01 04 e8 90 01 04 68 26 80 ac c8 90 00 } //01 00 
		$a_01_3 = {47 65 74 42 6f 74 49 64 65 6e 74 00 50 6c 67 } //00 00 
	condition:
		any of ($a_*)
 
}