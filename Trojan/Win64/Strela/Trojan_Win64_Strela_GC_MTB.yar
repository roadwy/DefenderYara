
rule Trojan_Win64_Strela_GC_MTB{
	meta:
		description = "Trojan:Win64/Strela.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 b9 10 00 00 00 4c 8d 05 8f 6a 01 00 48 8d 15 88 6a 01 00 33 c9 } //10
		$a_01_1 = {41 b9 10 00 00 00 4c 8d 05 3f 6a 01 00 48 8d 15 38 6a 01 00 33 c9 } //10
		$a_01_2 = {41 b8 00 30 00 00 41 b9 40 00 00 00 31 c9 } //1
		$a_01_3 = {45 6e 74 72 79 } //1 Entry
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=11
 
}