
rule TrojanDropper_O97M_GraceWire_AH_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.AH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {3d 20 55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67 20 2b 20 22 5c 63 6f 6e 74 72 61 63 74 5f 22 } //1
		$a_01_1 = {45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 20 22 43 41 4c 4c 28 22 22 22 20 2b } //1 ExecuteExcel4Macro "CALL(""" +
		$a_01_2 = {65 78 61 6d 70 6c 65 73 2f 6d 65 64 69 61 2f 77 61 76 65 2e 6d 70 33 } //1 examples/media/wave.mp3
		$a_01_3 = {56 42 43 6f 6d 70 6f 6e 65 6e 74 45 78 69 73 74 73 28 22 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 22 2c } //1 VBComponentExists("ThisWorkbook",
		$a_01_4 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 2e 43 6f 70 79 } //1 ThisWorkbook.Sheets.Copy
		$a_01_5 = {3d 20 22 2f 62 6c 6f 62 22 20 26 20 43 53 74 72 28 47 65 74 52 61 6e 2e 64 6f 6d 49 6e 74 65 67 65 72 28 29 29 20 26 20 22 3a 22 } //1 = "/blob" & CStr(GetRan.domInteger()) & ":"
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}