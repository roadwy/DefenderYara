
rule Trojan_Win32_Pony_ASC_MTB{
	meta:
		description = "Trojan:Win32/Pony.ASC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {97 c9 29 94 e7 ca 43 d0 0e 35 a6 c4 07 ad 41 80 b1 57 b9 4a f8 6e 4f 02 ec c3 } //01 00 
		$a_01_1 = {86 24 f3 38 e0 92 30 21 c5 5c 86 03 0a 8b 59 bb 1a 53 19 85 aa 6c 35 6e 1d aa a3 99 d1 25 2a 53 df ed 3a e7 71 } //01 00 
		$a_01_2 = {f6 91 be cf 3c 8b 86 64 88 55 15 56 f0 de 94 6c e7 b1 30 47 c4 30 d6 62 0c a4 8a 62 9d } //01 00 
		$a_01_3 = {ba 3c d9 d2 ff c0 e8 2e 92 bc c9 5c 5d e1 35 98 95 6c 8d 15 b4 27 c9 30 d6 05 be bb 6d f5 } //00 00 
	condition:
		any of ($a_*)
 
}