
rule Ransom_MSIL_Crjoker{
	meta:
		description = "Ransom:MSIL/Crjoker,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 00 7b 00 6f 00 6e 00 7b 00 65 00 79 00 20 00 7b 00 67 00 65 00 6f 00 7b 00 72 00 67 00 7b 00 65 00 } //01 00  M{on{ey {geo{rg{e
		$a_01_1 = {5f 00 44 00 61 00 6e 00 5f 00 67 00 5f 00 65 00 72 00 5f 00 6f 00 75 00 5f 00 73 00 5f 00 20 00 46 00 72 00 5f 00 65 00 5f 00 73 00 68 00 } //01 00  _Dan_g_er_ou_s_ Fr_e_sh
		$a_01_2 = {53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 71 00 75 00 57 00 68 00 65 00 6e 00 65 00 76 00 65 00 72 00 41 00 6d 00 65 00 72 00 69 00 63 00 61 00 69 00 63 00 6b 00 } //01 00  Service quWheneverAmericaick
		$a_01_3 = {51 00 75 00 69 00 63 00 6b 00 6c 00 79 00 4c 00 69 00 76 00 65 00 2e 00 65 00 78 00 65 00 } //00 00  QuicklyLive.exe
	condition:
		any of ($a_*)
 
}