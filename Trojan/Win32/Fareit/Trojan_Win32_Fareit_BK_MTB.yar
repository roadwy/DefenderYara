
rule Trojan_Win32_Fareit_BK_MTB{
	meta:
		description = "Trojan:Win32/Fareit.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 4b 41 30 e7 2c 2b 2b 40 40 a8 7b 4d 2e 33 34 34 3a 34 8d a4 66 43 3c 59 2a 2a 2f 2f d2 36 2d 2d 2b 2c 2c 30 41 4c 68 3f 62 62 86 86 86 62 62 3f 61 4c 41 30 30 3b 45 e6 } //01 00 
		$a_01_1 = {33 33 58 5d 34 ac 80 64 2a 2a 2a 2a 2a 2a 2f 2f d2 31 2d 2b 2b 2c 30 41 4c 61 3f 62 86 5c 54 c7 54 5c 73 } //01 00 
		$a_01_2 = {69 55 5c ae c4 51 05 35 e7 35 4a 4a 35 c2 e5 6d 37 32 39 38 3e 44 2a 43 2a 66 2a 2a 36 36 40 2d 2b 2c 30 30 4c } //00 00 
	condition:
		any of ($a_*)
 
}