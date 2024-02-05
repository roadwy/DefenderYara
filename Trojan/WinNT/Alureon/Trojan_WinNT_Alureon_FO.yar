
rule Trojan_WinNT_Alureon_FO{
	meta:
		description = "Trojan:WinNT/Alureon.FO,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 ae 4e 00 00 66 03 01 b9 56 a1 00 00 66 33 c1 8b 4d f4 03 4d 10 0f b7 c0 66 89 01 8b 45 f8 8b 4d 0c } //01 00 
		$a_01_1 = {04 2d 34 e3 88 01 41 42 8a 02 3c b6 75 } //01 00 
		$a_01_2 = {c7 06 84 6a 62 73 c7 46 04 5f 61 66 64 c7 46 08 59 63 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}