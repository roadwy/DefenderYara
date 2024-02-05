
rule Ransom_Win64_Nokoyawa_AB{
	meta:
		description = "Ransom:Win64/Nokoyawa.AB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //0a 00 
		$a_03_1 = {80 00 00 00 c7 44 24 20 03 00 00 00 45 33 c9 41 b8 03 00 00 00 ba 9f 01 12 00 48 8b 8c 90 01 05 ff 15 90 00 } //0a 00 
		$a_03_2 = {41 b9 18 00 00 00 4c 8d 44 90 01 02 ba 28 c0 53 00 48 8b 4c 90 01 02 ff 15 90 00 } //00 00 
		$a_00_3 = {5d 04 00 00 b8 21 05 80 5c 2e 00 00 b9 21 05 80 00 00 01 00 } //32 00 
	condition:
		any of ($a_*)
 
}