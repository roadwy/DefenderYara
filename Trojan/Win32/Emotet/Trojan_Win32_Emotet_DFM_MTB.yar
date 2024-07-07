
rule Trojan_Win32_Emotet_DFM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {81 e1 ff 00 00 00 03 c1 b9 90 01 04 99 f7 f9 8a 03 83 c4 18 8a 54 14 14 32 c2 88 03 90 00 } //1
		$a_81_1 = {6e 77 61 59 32 72 6e 38 35 44 38 59 77 56 63 79 7a 78 46 65 57 4b 50 55 33 4d 38 6c 31 62 } //1 nwaY2rn85D8YwVcyzxFeWKPU3M8l1b
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_DFM_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.DFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {f7 e6 8b c6 2b c2 d1 e8 03 c2 8b 54 24 0c c1 e8 05 6b c0 23 8b ce 2b c8 8a 04 11 30 04 3e } //1
		$a_81_1 = {62 43 75 4e 55 6b 2a 64 7c 50 51 64 37 6c 23 7c 57 40 31 52 40 63 4b 7b 50 33 6a 40 47 6e 71 41 61 4c } //1 bCuNUk*d|PQd7l#|W@1R@cK{P3j@GnqAaL
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}