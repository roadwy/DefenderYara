
rule Trojan_Win64_Tedy_ASU_MTB{
	meta:
		description = "Trojan:Win64/Tedy.ASU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_03_0 = {5e f6 66 24 80 b1 ?? ?? ?? ?? 9a c8 b9 4e a2 68 0d 41 29 3c 24 b3 05 f2 b2 8e d7 35 14 0f 87 de 53 71 } //5
		$a_01_1 = {bb f0 27 ba ff f3 0c b5 30 cc ec ed 5c 80 31 e7 } //5
		$a_01_2 = {64 25 12 a4 6c 35 bc cb ea b9 c9 2d 17 23 6d 7f 97 34 b6 e2 3e } //5
		$a_01_3 = {33 29 89 24 74 20 c3 45 2b ed } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5) >=10
 
}