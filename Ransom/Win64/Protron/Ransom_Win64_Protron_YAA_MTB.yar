
rule Ransom_Win64_Protron_YAA_MTB{
	meta:
		description = "Ransom:Win64/Protron.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {34 42 39 39 31 33 36 39 2d 37 43 37 43 2d 34 37 41 41 2d 41 38 31 45 2d 45 46 36 45 44 31 46 35 45 32 34 43 } //1 4B991369-7C7C-47AA-A81E-EF6ED1F5E24C
		$a_03_1 = {2b c1 6b c8 23 b8 90 01 04 f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 83 c1 7f b8 90 01 04 f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 90 00 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}