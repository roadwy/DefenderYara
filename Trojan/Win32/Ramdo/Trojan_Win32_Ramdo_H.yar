
rule Trojan_Win32_Ramdo_H{
	meta:
		description = "Trojan:Win32/Ramdo.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 fe 70 17 00 00 7c ac 83 ff 65 76 18 8b c7 89 45 ec } //01 00 
		$a_01_1 = {2b 45 f0 33 d2 b9 10 27 00 00 f7 f1 3d 60 ea 00 00 0f } //01 00 
		$a_01_2 = {2b 4d f0 b8 59 17 b7 d1 f7 e1 c1 ea 0d 81 fa 60 ea 00 00 0f } //01 00 
		$a_01_3 = {68 3e dd ef 6c 6a 03 6a 00 e8 } //01 00 
		$a_01_4 = {68 df c3 86 5d 6a 01 6a 00 e8 } //01 00 
		$a_01_5 = {68 7b 17 76 c0 6a 03 6a 00 e8 } //01 00 
		$a_01_6 = {68 4f b7 1c 9c 6a 03 6a 00 e8 } //01 00 
		$a_01_7 = {68 89 48 f7 23 6a 03 6a 00 e8 } //01 00 
		$a_01_8 = {68 11 86 93 3f 6a 03 6a 00 e8 } //01 00 
		$a_01_9 = {68 87 31 b8 51 6a 03 6a 00 e8 } //01 00 
		$a_01_10 = {68 bc 88 2a 42 6a 03 6a 00 e8 } //01 00 
		$a_01_11 = {68 45 7d 80 db 6a 03 56 e8 } //00 00 
	condition:
		any of ($a_*)
 
}