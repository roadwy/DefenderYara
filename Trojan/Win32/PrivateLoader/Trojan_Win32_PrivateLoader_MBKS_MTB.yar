
rule Trojan_Win32_PrivateLoader_MBKS_MTB{
	meta:
		description = "Trojan:Win32/PrivateLoader.MBKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {7a 75 66 69 78 75 76 61 6a 61 70 69 64 75 6d 6f 66 69 6b 6f 78 69 67 6f 73 6f 73 75 73 6f 6e 69 } //01 00  zufixuvajapidumofikoxigososusoni
		$a_01_1 = {76 65 7a 65 78 } //01 00  vezex
		$a_01_2 = {6e 65 70 75 6a 69 6a 6f 74 65 62 61 79 75 6e 69 } //01 00  nepujijotebayuni
		$a_01_3 = {67 75 79 65 62 65 70 65 68 69 78 75 74 75 6d 75 64 61 68 69 76 75 66 61 6c 61 64 6f 76 6f 70 75 20 68 6f 6c 65 6c 69 74 20 63 65 6a 65 62 6f 64 65 6d 75 63 65 66 65 76 6f 6a 61 77 65 20 6b 65 77 61 76 65 73 69 72 6f 73 } //01 00  guyebepehixutumudahivufaladovopu holelit cejebodemucefevojawe kewavesiros
		$a_01_4 = {68 75 76 75 63 65 6b 61 66 6f 64 } //01 00  huvucekafod
		$a_01_5 = {6d 65 73 75 6a 6f 7a 69 62 75 7a 65 72 61 6b 61 74 75 62 75 6b 75 6c 69 78 75 62 69 66 69 } //01 00  mesujozibuzerakatubukulixubifi
		$a_01_6 = {6e 61 72 69 6e 6f 67 69 79 75 64 61 72 6f 74 65 66 69 6c 61 77 61 7a 75 74 75 70 61 } //01 00  narinogiyudarotefilawazutupa
		$a_01_7 = {64 69 67 65 74 65 6b 75 67 61 62 69 67 75 74 75 72 61 6c 20 63 6f 7a 65 64 61 63 75 6d 6f 70 65 63 69 62 6f 63 65 74 6f 68 69 6a 65 66 65 62 6f 66 65 20 64 75 64 69 73 69 6e 61 64 65 79 75 7a 69 6c 6f 67 6f 6b 6f 64 } //00 00  digetekugabigutural cozedacumopecibocetohijefebofe dudisinadeyuzilogokod
	condition:
		any of ($a_*)
 
}