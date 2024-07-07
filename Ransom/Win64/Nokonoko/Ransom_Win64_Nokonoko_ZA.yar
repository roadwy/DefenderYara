
rule Ransom_Win64_Nokonoko_ZA{
	meta:
		description = "Ransom:Win64/Nokonoko.ZA,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {41 0f be 10 4d 8d 40 01 8b c8 c1 e8 90 01 01 48 33 d1 0f b6 ca 41 33 04 8f 49 83 e9 01 75 e3 f7 d0 3b c6 74 27 90 00 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}