
rule Trojan_Win32_AutoitInject_AMBG_MTB{
	meta:
		description = "Trojan:Win32/AutoitInject.AMBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c9 38 6e a5 c9 a1 2f b0 88 a6 fd a2 89 6f e6 6b a0 28 ee 92 37 c4 a3 ae 9b 5d 72 b3 cd 21 0e 4f de ed 27 0a 91 15 e8 b6 b0 57 6a 8b 0c 39 41 91 } //01 00 
		$a_01_1 = {79 f8 1d bc 70 ef 9a 68 74 6f 21 44 38 a8 a7 a3 fe fe ca 11 a9 98 3c ba 92 b2 e2 54 b9 da 69 2f e5 aa 92 22 e9 b4 34 43 78 16 0a e6 69 4a 1c 6e } //00 00 
	condition:
		any of ($a_*)
 
}