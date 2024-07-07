
rule Ransom_Win32_BlackCat_ZA_MTB{
	meta:
		description = "Ransom:Win32/BlackCat.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc9 00 ffffffc9 00 03 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_01_1 = {89 d3 89 c8 31 d2 f7 f6 8b 45 f0 0f b6 04 10 89 da 30 04 0b 41 39 cf } //100
		$a_03_2 = {8b 0e 8a 15 90 01 04 88 14 01 ff 46 08 a2 90 00 } //100
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*100+(#a_03_2  & 1)*100) >=201
 
}