
rule Ransom_Win32_Lyposit_D{
	meta:
		description = "Ransom:Win32/Lyposit.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 7d d4 6c 80 7d fe 75 10 81 7d d8 a3 1f c3 d9 75 07 c7 45 e4 01 00 00 00 } //01 00 
		$a_01_1 = {89 45 d8 8b 45 d8 c7 00 0c b1 37 13 6a 10 } //01 00 
		$a_01_2 = {33 45 d8 33 55 dc 89 45 d8 89 55 dc 8b 45 e4 0f b6 08 83 e1 3f } //01 00 
		$a_01_3 = {eb 26 c1 c2 06 8b c2 24 3f 3c 3e 73 12 3c 34 73 0a 04 41 3c 5b } //01 00 
		$a_01_4 = {0f be 04 10 8b 4d 08 03 4d f8 0f be 09 33 c1 88 45 f6 8b 45 f8 33 d2 6a 03 } //00 00 
	condition:
		any of ($a_*)
 
}