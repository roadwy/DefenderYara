
rule Ransom_Win32_Nokonoko_ZA{
	meta:
		description = "Ransom:Win32/Nokonoko.ZA,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {0f be 0e 8d 76 01 33 90 01 01 c1 90 01 02 0f b6 c9 33 90 01 01 8d 70 90 01 03 83 90 01 01 01 75 e6 90 00 } //10
		$a_01_2 = {fc 70 79 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10+(#a_01_2  & 1)*1) >=12
 
}