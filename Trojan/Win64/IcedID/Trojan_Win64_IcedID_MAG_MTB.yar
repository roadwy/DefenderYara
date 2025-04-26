
rule Trojan_Win64_IcedID_MAG_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {48 58 4e 61 4b 6b 52 } //1 HXNaKkR
		$a_01_1 = {4d 74 46 55 69 46 39 54 71 66 4f } //1 MtFUiF9TqfO
		$a_01_2 = {4f 6e 6d 47 43 62 7a } //1 OnmGCbz
		$a_01_3 = {57 77 37 4a 4d 64 43 5a 6c 53 } //1 Ww7JMdCZlS
		$a_01_4 = {68 4b 67 4a 4d 55 33 61 46 30 63 } //1 hKgJMU3aF0c
		$a_01_5 = {47 59 75 73 64 6b 6e 73 61 } //1 GYusdknsa
		$a_01_6 = {51 31 65 36 6c 55 77 45 } //1 Q1e6lUwE
		$a_01_7 = {63 69 62 4f 62 48 45 6d } //1 cibObHEm
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}