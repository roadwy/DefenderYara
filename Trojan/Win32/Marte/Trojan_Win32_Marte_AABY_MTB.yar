
rule Trojan_Win32_Marte_AABY_MTB{
	meta:
		description = "Trojan:Win32/Marte.AABY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {46 47 69 6f 6f 66 69 61 65 69 65 6a 67 } //1 FGioofiaeiejg
		$a_01_1 = {46 67 69 73 6f 65 67 69 6f 61 65 67 6a 61 64 66 } //1 Fgisoegioaegjadf
		$a_01_2 = {4e 6f 69 61 69 6f 66 67 61 65 6a 67 61 6a 44 6f 61 67 64 } //1 NoiaiofgaejgajDoagd
		$a_01_3 = {4f 69 6f 61 70 66 6a 69 6f 61 64 6a 66 67 64 6a } //1 Oioapfjioadjfgdj
		$a_01_4 = {50 61 64 66 70 6f 69 61 6a 67 69 61 65 64 6a 67 6a } //1 Padfpoiajgiaedjgj
		$a_01_5 = {59 69 74 69 73 61 67 69 61 73 65 67 61 69 73 64 6f 6b 78 } //1 Yitisagiasegaisdokx
		$a_01_6 = {6f 69 6f 61 69 64 66 6a 61 6f 65 69 67 68 61 75 65 68 67 } //1 oioaidfjaoeighauehg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}