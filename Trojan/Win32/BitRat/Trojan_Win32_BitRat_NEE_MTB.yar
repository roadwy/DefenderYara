
rule Trojan_Win32_BitRat_NEE_MTB{
	meta:
		description = "Trojan:Win32/BitRat.NEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 4a a2 b7 e3 04 cd 9e 91 33 b6 11 61 34 66 40 df 4f 9d 3d 14 04 4f c5 e5 3b ff cc 31 00 00 b2 fc d4 c9 f0 e4 91 44 92 6a 70 81 94 93 f7 f3 d6 5a 6b 54 49 26 45 47 9e 5d 43 1d 8c 9e 43 d6 } //01 00 
		$a_01_1 = {73 74 64 6f 6c 65 32 2e 74 6c 62 } //01 00 
		$a_01_2 = {4c 00 79 00 6e 00 78 00 47 00 72 00 69 00 64 00 2e 00 76 00 62 00 70 00 } //01 00 
		$a_01_3 = {50 00 61 00 74 00 72 00 69 00 63 00 69 00 61 00 } //00 00 
	condition:
		any of ($a_*)
 
}