
rule Trojan_Win32_Strilix_A_dha{
	meta:
		description = "Trojan:Win32/Strilix.A!dha,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {59 57 68 80 00 00 00 6a 03 57 6a 07 8b d8 68 00 00 00 80 56 89 3b } //0a 00 
		$a_01_1 = {b9 50 85 33 01 81 e9 00 10 33 01 83 c1 fb 03 c8 } //05 00 
		$a_01_2 = {c7 06 44 33 22 11 89 9e b0 00 00 00 89 5e 10 89 5e 14 89 5e 18 89 5e 1c 89 5e 20 89 5e 74 } //05 00 
		$a_01_3 = {c7 00 44 33 22 11 48 89 b0 d8 00 00 00 48 89 70 10 48 89 70 18 89 70 20 48 89 70 74 b8 20 00 00 00 ba b0 10 00 00 44 8d 48 e4 33 c9 } //00 00 
	condition:
		any of ($a_*)
 
}