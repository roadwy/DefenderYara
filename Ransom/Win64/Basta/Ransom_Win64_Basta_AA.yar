
rule Ransom_Win64_Basta_AA{
	meta:
		description = "Ransom:Win64/Basta.AA,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //0a 00 
		$a_03_1 = {0f 57 c0 33 c0 48 89 45 70 0f 29 85 b0 00 00 00 f2 0f 10 45 70 f2 0f 11 85 c0 00 00 00 48 8d 95 b0 00 00 00 48 8d 4c 24 50 e8 90 01 04 41 b8 3e 42 00 00 48 8d 15 90 01 04 48 8d 4c 24 50 e8 90 01 04 48 8d 4c 24 50 e8 90 01 04 48 8d 4c 24 58 e8 90 00 } //00 00 
		$a_00_2 = {5d 04 00 00 35 7c 05 80 5c 2c } //00 00 
	condition:
		any of ($a_*)
 
}