
rule Trojan_Win64_Latrodectus_MEA_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.MEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 03 c3 41 c1 e0 02 41 0f b6 c1 41 fe c1 41 03 c0 8a 0c 18 30 0a 48 ff c2 41 80 f9 04 72 e8 } //3
		$a_01_1 = {41 32 c2 4d 8d 76 04 32 c3 40 32 c7 40 32 c6 41 88 46 fd 48 83 ed 01 } //3
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3) >=6
 
}