
rule Trojan_Win32_Mobsularch_A{
	meta:
		description = "Trojan:Win32/Mobsularch.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {d0 9a d0 be d0 b4 20 d0 b0 d0 ba d1 82 d0 b8 d0 b2 d0 b0 d1 86 d0 b8 d0 b8 } //01 00 
		$a_01_1 = {d0 a1 d1 82 d0 be d0 b8 d0 bc d0 be d1 81 d1 82 d1 8c 20 53 4d 53 2d d1 81 d0 be d0 be d0 b1 d1 89 d0 b5 d0 bd d0 b8 d1 8f 20 } //01 00 
		$a_01_2 = {d0 b2 d0 b2 d0 b5 d1 81 d1 82 d0 b8 20 d0 bd d0 be d0 bc d0 b5 d1 80 20 d1 81 d0 b2 d0 be d0 b5 d0 b3 d0 be 20 d0 bc d0 be d0 b1 d0 b8 d0 bb d1 8c d0 bd d0 be d0 b3 d0 be 20 d1 82 d0 b5 d0 bb d0 b5 d1 84 d0 be d0 bd d0 b0 } //01 00 
		$a_01_3 = {d0 bd d0 be d0 bc d0 b5 d1 80 3a 20 d0 bd d0 b0 20 d0 bd d0 b5 d0 b3 d0 be 20 d0 bf d1 80 d0 b8 d0 b4 d0 b5 d1 82 20 d0 bf d1 80 d0 be d0 b2 d0 b5 d1 80 d0 be d1 87 d0 bd d1 8b d0 b9 20 d0 ba d0 be d0 b4 } //05 00 
		$a_01_4 = {2f 00 63 00 75 00 73 00 74 00 6f 00 6d 00 65 00 72 00 73 00 2f 00 61 00 70 00 70 00 5f 00 6c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 70 00 68 00 70 00 3f 00 69 00 64 00 5f 00 70 00 72 00 6f 00 6a 00 65 00 63 00 74 00 3d 00 } //00 00 
	condition:
		any of ($a_*)
 
}