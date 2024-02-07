
rule TrojanDownloader_O97M_Zinunlate_A{
	meta:
		description = "TrojanDownloader:O97M/Zinunlate.A,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 28 37 34 2c 20 22 31 65 7a 37 61 74 6e 38 6c 61 75 37 6c 69 6e 22 2c 20 34 31 29 29 20 3c 3e 20 30 } //01 00  s(74, "1ez7atn8lau7lin", 41)) <> 0
		$a_01_1 = {73 28 32 36 37 2c 20 22 74 6a 63 69 69 73 62 53 74 46 79 4f 74 70 2e 53 6d 63 69 67 65 65 65 72 6e 6c 22 2c 20 34 37 29 29 } //01 00  s(267, "tjciisbStFyOtp.Smcigeeernl", 47))
		$a_01_2 = {73 28 37 38 2c 20 22 65 2e 66 6e 74 5a 65 72 49 69 65 69 6f 6e 3a 64 22 2c 20 31 36 37 29 } //01 00  s(78, "e.fntZerIieion:d", 167)
		$a_01_3 = {73 28 34 32 2c 20 22 68 74 72 57 65 2e 69 53 6c 53 70 63 6c 22 2c 20 39 35 29 29 } //01 00  s(42, "htrWe.iSlSpcl", 95))
		$a_01_4 = {65 65 6d 68 70 6d 73 29 65 61 24 65 5d 74 64 75 65 29 6c 2e 2f 2e 72 49 77 44 61 4e 45 74 74 28 2f 63 53 65 6c 7a 2c 53 74 65 6f 2e 62 24 46 65 70 74 53 6d 4e 29 6c 3b 29 47 79 6c 6c 20 3d 61 62 75 6e 74 50 62 6e 38 2d 63 6d 2e 74 64 20 74 3b 6e 74 66 6c 3a 20 46 2f 63 24 65 57 2f 62 69 4f 2d 6f 31 65 78 54 65 27 75 6f 79 28 69 69 20 68 68 63 61 65 6a 66 69 74 3a 65 63 2e 65 2e 6c 28 2e 65 73 65 69 2d 5b 6d 43 6e 27 2e 61 6a 6c 37 4f 28 70 4e 74 61 57 65 28 74 65 29 6c 3a 53 69 63 74 66 4e 65 6e 69 70 2e 4f 77 37 77 } //01 00  eemhpms)ea$e]tdue)l./.rIwDaNEtt(/cSelz,Steo.b$FeptSmN)l;)Gyll =abuntPbn8-cm.td t;ntfl: F/c$eW/biO-o1exTe'uoy(ii hhcaejfit:ec.e.l(.esei-[mCn'.ajl7O(pNtaWe(te)l:SictfNenip.Ow7w
		$a_01_5 = {73 28 35 31 2c 20 22 70 65 63 2e 6c 69 68 53 74 6c 72 53 57 22 2c 20 31 32 35 29 29 } //01 00  s(51, "pec.lihStlrSW", 125))
		$a_01_6 = {28 31 30 33 2c 20 39 39 2c 20 22 70 65 63 2e 6c 69 68 53 74 6c 72 53 57 22 29 } //00 00  (103, 99, "pec.lihStlrSW")
	condition:
		any of ($a_*)
 
}