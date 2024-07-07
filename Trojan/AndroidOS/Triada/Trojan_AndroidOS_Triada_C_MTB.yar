
rule Trojan_AndroidOS_Triada_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Triada.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {12 01 21 73 6e 10 90 01 02 08 00 0a 04 01 10 01 12 35 32 14 00 34 40 03 00 01 10 48 05 07 02 6e 20 90 01 02 08 00 0a 06 b7 65 8d 55 4f 05 07 02 d8 02 02 01 d8 00 00 01 28 ed 11 07 90 00 } //2
		$a_00_1 = {63 6f 6d 2f 66 6f 75 72 71 61 7a 2f 73 69 78 77 73 78 } //1 com/fourqaz/sixwsx
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1) >=3
 
}