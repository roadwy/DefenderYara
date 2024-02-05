
rule Backdoor_Win32_Blohi_gen_A{
	meta:
		description = "Backdoor:Win32/Blohi.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 00 73 00 20 00 2d 00 66 00 20 00 2d 00 74 00 20 00 } //01 00 
		$a_01_1 = {23 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 4c 00 23 00 } //01 00 
		$a_01_2 = {48 00 61 00 63 00 6b 00 65 00 72 00 20 00 2d 00 2d 00 3e 00 20 00 } //01 00 
		$a_01_3 = {23 00 52 00 65 00 6d 00 6f 00 74 00 65 00 41 00 23 00 } //00 00 
	condition:
		any of ($a_*)
 
}