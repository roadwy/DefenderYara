
rule Ransom_Win32_LockScreen_BN{
	meta:
		description = "Ransom:Win32/LockScreen.BN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c4 e8 f1 ef e5 f2 f7 e5 f0 20 e7 e0 e4 e0 f7 20 57 69 6e 64 6f 77 73 00 } //01 00 
		$a_01_1 = {d0 b8 d1 82 d0 b5 20 d0 b2 d0 ba d0 bb d0 b0 d0 b4 d0 ba d1 83 20 22 57 65 62 4d 6f 6e 65 79 22 } //01 00 
		$a_01_2 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00 6f 70 65 6e 00 00 00 00 65 78 70 6c 6f 72 65 72 00 00 00 00 ff ff ff ff 0c 00 00 00 cd e5 e2 e5 } //00 00 
		$a_00_3 = {87 } //10 00 
	condition:
		any of ($a_*)
 
}