
rule Trojan_Win64_Rhadamanthys_NR_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8d 45 bf c6 45 ef 01 48 89 44 24 28 45 33 c9 48 83 64 24 20 00 45 33 c0 33 d2 c7 45 eb 16 00 00 00 33 c9 e8 35 5b fe ff 83 cf ff } //2
		$a_01_1 = {74 0f 8b 5d eb 48 8d 4d bf e8 6d 5c fe ff 89 58 20 80 7d f7 00 74 0f 8b 5d f3 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}