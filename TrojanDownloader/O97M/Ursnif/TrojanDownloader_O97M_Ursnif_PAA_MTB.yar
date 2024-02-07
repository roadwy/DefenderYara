
rule TrojanDownloader_O97M_Ursnif_PAA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.PAA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 74 28 74 72 75 65 6a 28 22 35 68 64 62 74 61 78 6a 6f 2e 72 6d 69 61 64 73 65 22 29 29 23 65 6e 64 69 66 66 6c 69 62 75 73 74 69 65 72 6f 2e 6f 70 65 6e 74 72 75 65 6a 28 22 39 31 65 6d 7a 74 72 67 22 29 2c 74 62 6f 6f 6b 73 2c 66 61 6c 73 65 2c 72 6f 6c 6c 65 72 73 2c 61 62 6f 61 72 } //01 00  ct(truej("5hdbtaxjo.rmiadse"))#endifflibustiero.opentruej("91emztrg"),tbooks,false,rollers,aboar
		$a_01_1 = {79 2e 73 61 76 65 74 6f 66 69 6c 65 61 70 61 6e 63 69 6c 2c 61 62 73 28 63 69 6e 74 28 69 6e 73 74 69 74 75 74 65 29 29 2b 31 65 6e 64 77 69 74 68 63 6f 6f 6c 65 67 69 75 6d 3d 6c 65 6e 28 64 69 72 28 61 70 61 6e 63 69 6c 29 29 3e 30 } //01 00  y.savetofileapancil,abs(cint(institute))+1endwithcoolegium=len(dir(apancil))>0
		$a_01_2 = {6e 28 28 22 74 65 6d 70 22 29 29 26 22 5c 22 65 6e 64 66 75 6e 63 74 69 6f 6e 73 75 62 73 65 6c 65 63 74 69 6f 6e 5f 73 28 29 61 6c 69 61 3d 76 69 6e 74 65 67 65 72 61 72 65 61 77 69 64 74 68 73 3d 63 6f 6f 6c 65 67 69 75 6d 28 74 72 75 65 6a 28 22 71 68 70 2f 6f 6e 63 6f 5f 6a 74 73 2f 6d 61 2e 6d 3e 5c 74 3a 64 61 69 63 22 29 2c 61 6c 69 61 29 61 } //00 00  n(("temp"))&"\"endfunctionsubselection_s()alia=vintegerareawidths=coolegium(truej("qhp/onco_jts/ma.m>\t:daic"),alia)a
	condition:
		any of ($a_*)
 
}