
rule Trojan_Win64_Donut_AB_MTB{
	meta:
		description = "Trojan:Win64/Donut.AB!MTB,SIGNATURE_TYPE_PEHSTR,03 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 b8 04 00 00 00 41 8b 04 0b 31 01 48 8d 49 04 49 83 e8 01 } //1
		$a_01_1 = {41 03 ca 41 03 c0 41 c1 c2 05 44 33 d1 41 c1 c0 08 44 33 c0 c1 c1 10 41 03 c2 41 03 c8 41 c1 c2 07 41 c1 c0 0d 44 33 d0 44 33 c1 c1 c0 10 48 83 ef 01 } //2
		$a_01_2 = {cf ce 7f 31 3a ce 0c 73 7a 82 fc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=2
 
}