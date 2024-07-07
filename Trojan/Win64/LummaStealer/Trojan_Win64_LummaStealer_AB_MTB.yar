
rule Trojan_Win64_LummaStealer_AB_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc9 00 ffffffc9 00 03 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_01_1 = {0f b6 3c 02 89 d9 80 e1 18 d3 e7 89 c1 83 e1 fc 31 7c 0c 14 40 83 c3 08 39 c6 75 e4 } //100
		$a_01_2 = {8d 1c ed 00 00 00 00 89 d9 80 e1 18 80 c9 07 31 c0 40 d3 e0 89 e9 83 e1 3c 31 44 0c 14 83 fe 38 } //100
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100) >=201
 
}