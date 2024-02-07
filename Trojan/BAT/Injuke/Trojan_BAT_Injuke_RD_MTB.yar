
rule Trojan_BAT_Injuke_RD_MTB{
	meta:
		description = "Trojan:BAT/Injuke.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 78 4e 59 44 77 71 69 79 49 78 6f 4e 53 57 6f 48 65 6c 4f 75 41 4c 61 6e 59 } //01 00  jxNYDwqiyIxoNSWoHelOuALanY
		$a_01_1 = {63 61 70 64 6f 6e 65 2e 65 78 65 } //01 00  capdone.exe
		$a_01_2 = {45 00 74 00 52 00 46 00 6b 00 58 00 46 00 41 00 41 00 6b 00 6a 00 67 00 66 00 4b 00 6d 00 41 00 74 00 41 00 4e 00 4f 00 44 00 46 00 74 00 51 00 6f 00 67 00 55 00 58 00 } //01 00  EtRFkXFAAkjgfKmAtANODFtQogUX
		$a_01_3 = {79 00 77 00 67 00 70 00 66 00 6f 00 75 00 } //01 00  ywgpfou
		$a_01_4 = {65 00 78 00 6d 00 74 00 65 00 65 00 6b 00 } //01 00  exmteek
		$a_01_5 = {70 00 63 00 6c 00 67 00 6c 00 71 00 71 00 } //01 00  pclglqq
		$a_01_6 = {66 00 66 00 74 00 76 00 66 00 66 00 62 00 } //01 00  fftvffb
		$a_01_7 = {79 00 69 00 76 00 6f 00 69 00 66 00 78 00 } //01 00  yivoifx
		$a_01_8 = {e2 81 ab e2 80 8c e2 81 ac e2 80 8c e2 80 8c e2 81 ac e2 81 ac e2 81 af e2 80 ab e2 80 ad e2 80 aa e2 81 aa e2 81 aa e2 80 ab e2 80 8e e2 81 ac e2 80 8c e2 81 ab e2 80 ab e2 80 8b e2 80 8c } //00 00 
	condition:
		any of ($a_*)
 
}