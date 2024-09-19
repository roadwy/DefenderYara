
rule Trojan_Win32_Neoreblamy_GPB_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 6f 76 6c 54 65 67 51 69 79 46 4e 62 7a 6d 50 41 } //1 UovlTegQiyFNbzmPA
		$a_01_1 = {77 51 4d 77 52 62 56 48 66 55 65 4c 72 69 54 66 76 } //3 wQMwRbVHfUeLriTfv
		$a_01_2 = {44 66 54 73 70 52 62 5a 47 63 6b 48 48 66 6d 59 43 54 61 73 59 66 63 } //5 DfTspRbZGckHHfmYCTasYfc
		$a_01_3 = {79 47 46 70 4d 4b 4e 79 66 4d 62 6b 41 72 4c 61 70 79 } //7 yGFpMKNyfMbkArLapy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_01_2  & 1)*5+(#a_01_3  & 1)*7) >=16
 
}