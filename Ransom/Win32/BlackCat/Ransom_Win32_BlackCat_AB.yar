
rule Ransom_Win32_BlackCat_AB{
	meta:
		description = "Ransom:Win32/BlackCat.AB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {83 c4 04 66 0f 6f 90 09 05 00 e8 90 0a 09 00 0f 29 90 0a 08 00 0f 29 90 00 } //5
		$a_03_2 = {83 c4 04 66 0f 6f 90 09 05 00 e8 90 0a 0b 00 66 0f 7f 90 0a 0b 00 0f 29 90 0a 07 00 0f 29 90 0a 0b 00 66 0f d4 90 00 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5) >=11
 
}