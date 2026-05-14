
rule Trojan_Win64_Formbook_RR_MTB{
	meta:
		description = "Trojan:Win64/Formbook.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {05 b9 79 37 9e 45 8b c8 41 c1 e1 04 44 03 4e 10 45 8d 1c 00 45 33 cb 45 8b d8 41 c1 eb 05 44 03 5e 14 45 33 cb 41 03 d1 44 8b ca 41 c1 e1 04 44 03 4e 18 44 8d 1c 02 45 33 cb 44 8b da 41 c1 eb 05 44 03 5e 1c 45 33 cb 45 03 c1 41 ff ca 75 } //1
		$a_01_1 = {4d 33 c2 4c 89 02 48 8d 56 18 4c 8b 0a 4c 03 4e 20 4c 89 0a 49 8b d1 48 c1 e2 11 49 c1 e9 2f 49 0b d1 48 89 56 18 48 8d 56 18 4d 8b c8 4c 33 0a 4c 89 0a 48 8d 56 20 4c 03 12 4c 89 12 49 8b d2 48 c1 e2 17 49 c1 ea 29 49 0b d2 48 89 56 20 48 8d 56 20 4c 33 0a 4c 89 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}