
rule Trojan_BAT_Gorgon_GJY_MTB{
	meta:
		description = "Trojan:BAT/Gorgon.GJY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {2f 43 20 74 68 61 6e 68 20 74 6f } ///C thanh to  01 00 
		$a_01_1 = {4d 79 6f 5a 70 33 67 5a 36 64 42 70 6c 4a 34 76 33 36 78 } //01 00  MyoZp3gZ6dBplJ4v36x
		$a_01_2 = {66 51 51 42 47 43 57 41 31 32 79 4c 4b 64 64 61 58 46 75 } //01 00  fQQBGCWA12yLKddaXFu
		$a_01_3 = {62 66 68 39 70 38 64 54 53 4c } //01 00  bfh9p8dTSL
		$a_01_4 = {46 51 68 65 41 52 37 42 4c 34 52 72 62 4e 65 63 45 45 53 } //01 00  FQheAR7BL4RrbNecEES
		$a_01_5 = {4d 55 30 32 70 32 4c 62 53 43 46 75 30 69 71 74 35 30 45 } //00 00  MU02p2LbSCFu0iqt50E
	condition:
		any of ($a_*)
 
}