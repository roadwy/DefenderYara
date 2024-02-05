
rule Trojan_Win32_Chanitor_A{
	meta:
		description = "Trojan:Win32/Chanitor.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {b0 20 2a c2 32 c3 42 88 04 0e 41 8a 19 84 db 75 } //01 00 
		$a_01_1 = {8d 0c 3a b0 12 2a c2 32 04 0b 42 88 01 3b d6 72 } //01 00 
		$a_01_2 = {4b 7a 6c 73 79 77 29 2b } //01 00 
		$a_01_3 = {3c 65 7f 7d 3c 7a 69 69 24 66 7a 60 } //01 00 
		$a_01_4 = {ed e9 9d eb ef 9b ef ee f8 e3 e2 96 e2 fd fb fc 8e fd e6 88 8b fc 81 eb 80 fd 81 83 87 f7 fb fc 89 fd 82 ff } //01 00 
		$a_01_5 = {66 c7 44 38 fd 65 78 c6 44 38 ff 65 } //00 00 
		$a_00_6 = {80 10 00 } //00 bb 
	condition:
		any of ($a_*)
 
}