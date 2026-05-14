
rule Trojan_Win64_Tedy_ABR_MTB{
	meta:
		description = "Trojan:Win64/Tedy.ABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {69 c0 6d 4e c6 41 05 39 30 00 00 89 c2 c1 ea 10 41 30 14 08 48 ff c1 } //5
		$a_80_1 = {73 61 6e 64 62 6f 78 6d 61 6c 77 61 72 65 76 69 72 75 73 73 61 6d 70 6c 65 74 65 73 74 61 6e 61 6c 79 73 69 73 } //sandboxmalwarevirussampletestanalysis  1
		$a_80_2 = {76 69 72 74 75 61 6c 76 62 6f 78 } //virtualvbox  1
	condition:
		((#a_01_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=7
 
}