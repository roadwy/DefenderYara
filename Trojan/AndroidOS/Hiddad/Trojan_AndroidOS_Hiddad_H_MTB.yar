
rule Trojan_AndroidOS_Hiddad_H_MTB{
	meta:
		description = "Trojan:AndroidOS/Hiddad.H!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 26 8d 19 85 42 09 d2 9d 5d 03 2e 94 5d 85 ea 04 05 9d 55 06 f1 01 05 2e 46 f2 d3 da f8 00 00 01 31 01 33 81 42 eb d3 99 f8 04 10 4d 1d a8 42 } //1
		$a_01_1 = {20 68 d0 f8 90 13 20 46 88 47 90 b9 20 68 29 46 32 46 43 46 d0 f8 78 c1 20 46 e0 47 05 46 20 68 d0 f8 90 13 20 46 88 47 20 b1 20 68 41 6c 20 46 88 47 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}