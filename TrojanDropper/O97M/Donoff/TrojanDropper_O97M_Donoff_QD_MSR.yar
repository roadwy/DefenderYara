
rule TrojanDropper_O97M_Donoff_QD_MSR{
	meta:
		description = "TrojanDropper:O97M/Donoff.QD!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 65 70 6c 61 63 65 28 22 43 23 23 23 3a 5c 23 23 23 57 69 6e 23 23 23 64 6f 23 23 23 77 73 5c 23 23 23 4d 69 63 72 23 23 23 6f 73 6f 66 23 23 23 74 2e 4e 45 54 5c 46 72 23 23 23 61 6d 65 77 6f 23 23 23 72 6b 5c 22 2c 20 22 23 23 23 22 2c 20 22 22 29 } //1 Replace("C###:\###Win###do###ws\###Micr###osof###t.NET\Fr###amewo###rk\", "###", "")
		$a_01_1 = {52 65 70 6c 61 63 65 28 22 5c 23 23 23 6d 73 23 23 23 62 75 23 23 23 69 6c 64 2e 23 23 23 65 78 65 22 2c 20 22 23 23 23 22 2c 20 22 22 29 } //1 Replace("\###ms###bu###ild.###exe", "###", "")
		$a_01_2 = {52 65 70 6c 61 63 65 28 22 55 23 23 23 53 45 23 23 23 52 50 23 23 23 52 4f 46 23 23 23 49 4c 45 22 2c 20 22 23 23 23 22 2c 20 22 22 29 29 20 26 20 22 5c 22 20 26 20 52 65 70 6c 61 63 65 28 22 44 23 23 23 6f 77 23 23 23 6e 6c 23 23 23 6f 61 23 23 23 64 73 22 2c 20 22 23 23 23 22 } //1 Replace("U###SE###RP###ROF###ILE", "###", "")) & "\" & Replace("D###ow###nl###oa###ds", "###"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}