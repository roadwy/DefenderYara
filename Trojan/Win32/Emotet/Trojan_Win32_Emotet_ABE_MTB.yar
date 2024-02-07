
rule Trojan_Win32_Emotet_ABE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.ABE!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 58 48 67 57 4c 53 77 41 65 62 3c 61 78 78 5e 35 5a 47 61 53 55 3f 29 71 37 30 50 4c 75 2b 71 64 23 70 25 33 73 38 32 51 37 24 21 6b 78 63 57 39 23 6f 40 56 56 37 54 4d 52 55 44 3c 76 76 23 6c 4d 28 42 73 39 52 2a 6c 50 4a 6d 64 65 21 69 5a 36 4c 38 52 6f 6c 23 2b 65 3f 4c 32 50 3f 38 37 5f 6e 31 5a 79 71 6a 37 68 } //00 00  TXHgWLSwAeb<axx^5ZGaSU?)q70PLu+qd#p%3s82Q7$!kxcW9#o@VV7TMRUD<vv#lM(Bs9R*lPJmde!iZ6L8Rol#+e?L2P?87_n1Zyqj7h
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_ABE_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.ABE!MTB,SIGNATURE_TYPE_PEHSTR,02 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {99 b9 fa 02 00 00 f7 f9 a1 c4 b0 04 10 0f af 05 c4 b0 04 10 2b d0 8b 0d b4 b0 04 10 0f af 0d b4 b0 04 10 03 15 c4 b0 04 10 03 ca 8b 15 c4 b0 04 10 0f af 15 c4 b0 04 10 2b ca a1 b4 b0 04 10 0f af 05 b4 b0 } //01 00 
		$a_01_1 = {5e 41 6c 77 65 24 66 36 59 61 66 71 41 51 31 52 46 6c 37 63 64 46 37 4f 35 70 30 44 67 3f 76 49 26 74 } //01 00  ^Alwe$f6YafqAQ1RFl7cdF7O5p0Dg?vI&t
		$a_01_2 = {d7 50 f9 8d 31 41 42 33 ae ef 35 9a d5 a6 78 7f 0e 4c 3e c2 be 42 cf bd d0 65 c9 3e 4a 2f 4a 62 e6 fa 76 65 e1 2d c6 47 47 51 ed 1a f1 47 9a f6 45 ea fe 27 5c 0d 33 a7 9f a9 6b f5 48 81 af e8 } //00 00 
	condition:
		any of ($a_*)
 
}