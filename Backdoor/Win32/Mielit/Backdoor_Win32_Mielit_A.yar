
rule Backdoor_Win32_Mielit_A{
	meta:
		description = "Backdoor:Win32/Mielit.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 6c 67 66 69 6c 65 73 } //01 00 
		$a_03_1 = {2a 20 53 52 33 56 90 09 0a 00 76 65 72 73 69 6f 6e 65 3d 2a 90 00 } //01 00 
		$a_01_2 = {63 68 69 61 76 65 77 69 6e 3d 52 69 73 6f 72 73 65 20 64 69 20 57 69 6e 64 6f 77 73 } //01 00 
		$a_01_3 = {48 34 35 4a 59 34 33 38 37 47 35 36 33 34 48 37 54 59 4e 48 43 37 38 33 48 35 34 37 33 35 48 44 34 48 43 } //00 00 
	condition:
		any of ($a_*)
 
}