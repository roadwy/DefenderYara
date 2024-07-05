
rule Trojan_Win32_DarkComet_ND_MTB{
	meta:
		description = "Trojan:Win32/DarkComet.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 74 72 63 70 79 41 6d 70 57 72 69 74 65 46 69 6c 65 } //01 00  strcpyAmpWriteFile
		$a_01_1 = {64 65 43 68 61 72 54 6f 4d 75 6c 74 69 42 79 42 } //01 00  deCharToMultiByB
		$a_01_2 = {56 69 42 61 6c 51 75 65 72 79 } //01 00  ViBalQuery
		$a_01_3 = {79 50 61 46 6f 72 53 48 67 58 4f 62 6a 50 74 } //01 00  yPaForSHgXObjPt
		$a_01_4 = {55 6e 68 41 64 5a 6a 70 } //01 00  UnhAdZjp
		$a_01_5 = {77 70 6f 68 4b 54 65 78 74 } //01 00  wpohKText
		$a_01_6 = {37 4a 41 74 6f 6d 41 } //00 00  7JAtomA
	condition:
		any of ($a_*)
 
}