
rule Trojan_Win64_Gozi_DK_MTB{
	meta:
		description = "Trojan:Win64/Gozi.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 29 d8 4d 63 c0 42 8a 04 00 42 32 04 0a 42 88 04 09 49 ff c1 e9 } //1
		$a_01_1 = {5a 36 5e 23 77 29 54 58 69 48 43 58 4f 67 37 44 70 4e 78 52 42 44 59 34 3e 79 59 43 73 } //1 Z6^#w)TXiHCXOg7DpNxRBDY4>yYCs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}