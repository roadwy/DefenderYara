
rule Trojan_O97M_JsDropper_C{
	meta:
		description = "Trojan:O97M/JsDropper.C,SIGNATURE_TYPE_MACROHSTR_EXT,15 00 14 00 03 00 00 "
		
	strings :
		$a_00_0 = {3d 20 22 53 22 20 26 20 43 68 72 28 39 35 20 2b 20 34 29 20 26 20 22 72 69 70 74 22 } //10 = "S" & Chr(95 + 4) & "ript"
		$a_00_1 = {3d 20 52 65 70 6c 61 63 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 46 75 6c 6c 4e 61 6d 65 2c 20 22 2e 64 6f 63 6d 22 2c 20 22 2e 7e 22 29 } //10 = Replace(ActiveDocument.FullName, ".docm", ".~")
		$a_02_2 = {50 72 69 6e 74 20 23 [0-10] 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 54 65 78 74 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_02_2  & 1)*1) >=20
 
}
rule Trojan_O97M_JsDropper_C_2{
	meta:
		description = "Trojan:O97M/JsDropper.C,SIGNATURE_TYPE_MACROHSTR_EXT,15 00 14 00 03 00 00 "
		
	strings :
		$a_00_0 = {3d 20 22 53 22 20 26 20 43 68 72 28 39 30 20 2b 20 39 29 20 26 20 22 72 22 20 26 20 22 69 70 74 22 } //10 = "S" & Chr(90 + 9) & "r" & "ipt"
		$a_00_1 = {3d 20 52 65 70 6c 61 63 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 46 75 6c 6c 4e 61 6d 65 2c 20 22 2e 64 22 20 26 20 22 6f 22 20 26 20 43 68 72 28 39 39 29 20 26 20 22 6d 22 2c 20 22 2e 64 22 20 26 20 22 61 74 22 29 } //10 = Replace(ActiveDocument.FullName, ".d" & "o" & Chr(99) & "m", ".d" & "at")
		$a_02_2 = {50 72 69 6e 74 20 23 [0-10] 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 54 65 78 74 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_02_2  & 1)*1) >=20
 
}