
rule Trojan_Win64_Emotet_AF_MTB{
	meta:
		description = "Trojan:Win64/Emotet.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {8b 0e 49 ff c3 48 8d 76 90 01 01 33 cd 0f b6 c1 66 41 89 00 0f b7 c1 c1 e9 10 66 c1 e8 08 4d 8d 40 90 01 01 66 41 89 40 90 01 01 0f b6 c1 66 c1 e9 90 01 01 66 41 89 40 90 01 01 66 41 89 48 90 01 01 4d 3b 90 01 01 72 90 00 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}