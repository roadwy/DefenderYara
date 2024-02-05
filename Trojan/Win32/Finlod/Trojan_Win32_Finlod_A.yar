
rule Trojan_Win32_Finlod_A{
	meta:
		description = "Trojan:Win32/Finlod.A,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 09 00 00 02 00 "
		
	strings :
		$a_01_0 = {c1 6d 68 ed } //02 00 
		$a_01_1 = {21 3b df 50 } //02 00 
		$a_01_2 = {91 fd 47 59 } //02 00 
		$a_01_3 = {7f 28 a0 69 } //02 00 
		$a_01_4 = {2f 44 d4 9b } //02 00 
		$a_01_5 = {fd 42 72 b6 } //01 00 
		$a_01_6 = {83 c0 30 ff d0 68 00 80 00 00 } //01 00 
		$a_01_7 = {48 83 c0 30 ff d0 41 b9 00 80 00 00 } //01 00 
		$a_01_8 = {5c 00 52 00 45 00 47 00 49 00 53 00 54 00 52 00 59 00 5c 00 } //00 00 
		$a_00_9 = {5d 04 00 00 52 2f 04 80 5c 2a 00 00 53 } //2f 04 
	condition:
		any of ($a_*)
 
}