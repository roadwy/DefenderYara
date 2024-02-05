
rule Trojan_Win32_BHO_F{
	meta:
		description = "Trojan:Win32/BHO.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 25 8d c3 50 5c 92 41 a7 46 ac 6f e5 19 83 1e d6 c9 ea 79 fa ba ce 11 8c 82 00 aa 00 4b a9 0b e8 c9 ea 79 f9 ba ce 11 8c 82 00 aa 00 4b a9 0b eb c9 ea 79 f9 ba ce 11 8c 82 00 aa 00 4b a9 0b ec c9 ea 79 f9 ba ce 11 8c 82 00 aa 00 4b a9 0b e4 c9 ea 79 f9 ba ce 11 8c 82 00 aa 00 4b a9 0b } //01 00 
		$a_01_1 = {5c 69 73 6f 63 6f 6e 66 69 67 2e 63 66 67 00 } //01 00 
		$a_00_2 = {2e 67 6f 32 65 61 73 79 2e 63 6f 6d 2f 69 73 6f } //01 00 
		$a_00_3 = {37 00 33 00 41 00 37 00 46 00 46 00 41 00 37 00 2d 00 41 00 41 00 33 00 41 00 2d 00 34 00 39 00 45 00 35 00 2d 00 41 00 37 00 37 00 37 00 2d 00 37 00 31 00 33 00 42 00 37 00 44 00 42 00 37 00 38 00 45 00 39 00 43 00 } //00 00 
	condition:
		any of ($a_*)
 
}