
rule Trojan_Win32_Marte_AABY_MTB{
	meta:
		description = "Trojan:Win32/Marte.AABY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 47 69 6f 6f 66 69 61 65 69 65 6a 67 } //01 00  FGioofiaeiejg
		$a_01_1 = {46 67 69 73 6f 65 67 69 6f 61 65 67 6a 61 64 66 } //01 00  Fgisoegioaegjadf
		$a_01_2 = {4e 6f 69 61 69 6f 66 67 61 65 6a 67 61 6a 44 6f 61 67 64 } //01 00  NoiaiofgaejgajDoagd
		$a_01_3 = {4f 69 6f 61 70 66 6a 69 6f 61 64 6a 66 67 64 6a } //01 00  Oioapfjioadjfgdj
		$a_01_4 = {50 61 64 66 70 6f 69 61 6a 67 69 61 65 64 6a 67 6a } //01 00  Padfpoiajgiaedjgj
		$a_01_5 = {59 69 74 69 73 61 67 69 61 73 65 67 61 69 73 64 6f 6b 78 } //01 00  Yitisagiasegaisdokx
		$a_01_6 = {6f 69 6f 61 69 64 66 6a 61 6f 65 69 67 68 61 75 65 68 67 } //00 00  oioaidfjaoeighauehg
	condition:
		any of ($a_*)
 
}