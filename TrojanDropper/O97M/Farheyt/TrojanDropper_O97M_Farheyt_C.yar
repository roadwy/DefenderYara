
rule TrojanDropper_O97M_Farheyt_C{
	meta:
		description = "TrojanDropper:O97M/Farheyt.C,SIGNATURE_TYPE_MACROHSTR_EXT,20 00 20 00 1c 00 00 "
		
	strings :
		$a_00_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 6f 72 64 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 CreateObject("Word.Application")
		$a_00_1 = {22 70 6d 31 } //5 "pm1
		$a_03_2 = {2e 56 69 73 69 62 6c 65 20 3d 20 46 61 6c 73 65 [0-1a] 2e 44 6f 63 75 6d 65 6e 74 73 2e 4f 70 65 6e 20 28 54 43 41 29 } //10
		$a_01_3 = {45 6e 76 69 72 6f 6e 24 28 } //5 Environ$(
		$a_01_4 = {22 72 74 22 20 26 20 43 68 72 28 31 30 32 29 } //10 "rt" & Chr(102)
		$a_03_5 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 61 76 65 41 73 20 46 69 6c 65 4e 61 6d 65 3a 3d [0-0a] 2c 20 46 69 6c 65 46 6f 72 6d 61 74 3a 3d 77 64 46 6f 72 6d 61 74 52 54 46 } //2
		$a_00_6 = {22 70 6d 33 22 20 26 20 22 22 20 2b 20 46 45 46 45 } //5 "pm3" & "" + FEFE
		$a_01_7 = {22 72 74 22 20 26 20 43 68 72 28 31 30 30 20 2b 20 32 29 } //10 "rt" & Chr(100 + 2)
		$a_00_8 = {22 74 74 31 22 20 26 20 22 22 20 2b 20 46 45 46 45 } //5 "tt1" & "" + FEFE
		$a_00_9 = {57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 } //3 Workbook_Open()
		$a_00_10 = {41 75 74 6f 5f 4f 70 65 6e 28 29 } //3 Auto_Open()
		$a_00_11 = {2e 51 75 69 74 0d 0a 53 65 74 20 } //3
		$a_00_12 = {43 68 72 28 31 31 34 29 20 26 20 43 68 72 28 31 31 36 29 20 26 20 43 68 72 28 31 30 32 29 } //6 Chr(114) & Chr(116) & Chr(102)
		$a_00_13 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 22 20 26 20 22 6f 72 64 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //2 = CreateObject("W" & "ord.Application")
		$a_00_14 = {20 2b 20 22 65 22 20 26 20 43 68 72 28 39 30 20 2b 20 } //2  + "e" & Chr(90 + 
		$a_00_15 = {20 3d 20 22 22 20 26 20 22 22 20 2b 20 22 54 22 20 2b 20 22 22 20 26 20 22 45 4d 22 20 2b 20 22 22 20 26 20 22 22 } //2  = "" & "" + "T" + "" & "EM" + "" & ""
		$a_03_16 = {56 69 73 69 62 6c 65 20 3d 20 46 61 6c 73 65 [0-1a] 2e 44 6f 63 75 6d 65 6e 74 73 2e 4f 70 65 6e 20 28 54 54 54 44 41 44 53 53 29 } //10
		$a_01_17 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 43 68 72 28 38 37 29 20 2b 20 22 6f 72 22 20 2b 20 22 64 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //2 = CreateObject(Chr(87) + "or" + "d.Application")
		$a_01_18 = {26 20 43 68 72 28 68 61 61 20 2b 20 31 31 37 29 20 26 20 22 66 22 } //5 & Chr(haa + 117) & "f"
		$a_01_19 = {22 72 22 20 26 20 43 68 72 28 68 61 61 20 2b 20 31 31 37 29 20 2b 20 22 22 20 26 20 22 66 22 } //7 "r" & Chr(haa + 117) + "" & "f"
		$a_03_20 = {56 61 6c 28 [0-0a] 29 20 2d 20 38 } //7
		$a_01_21 = {22 45 4d 22 20 2b 20 22 50 22 } //5 "EM" + "P"
		$a_01_22 = {22 6f 72 22 20 2b 20 22 64 2e 41 22 20 26 20 22 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //7 "or" + "d.A" & "pplication")
		$a_01_23 = {22 72 74 22 20 26 20 22 66 22 } //5 "rt" & "f"
		$a_01_24 = {3d 20 22 45 22 20 26 20 22 4d 22 } //7 = "E" & "M"
		$a_03_25 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-30] 29 0d 0a [0-15] 2e 56 69 73 69 62 6c 65 20 3d 20 46 61 6c 73 65 } //5
		$a_01_26 = {22 2e 41 22 20 26 20 22 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //7 ".A" & "pplication")
		$a_03_27 = {4d 6f 64 75 6c 65 31 2e [0-0a] 20 28 31 29 0d 0a [0-0a] 2e 51 75 69 74 } //7
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*5+(#a_03_2  & 1)*10+(#a_01_3  & 1)*5+(#a_01_4  & 1)*10+(#a_03_5  & 1)*2+(#a_00_6  & 1)*5+(#a_01_7  & 1)*10+(#a_00_8  & 1)*5+(#a_00_9  & 1)*3+(#a_00_10  & 1)*3+(#a_00_11  & 1)*3+(#a_00_12  & 1)*6+(#a_00_13  & 1)*2+(#a_00_14  & 1)*2+(#a_00_15  & 1)*2+(#a_03_16  & 1)*10+(#a_01_17  & 1)*2+(#a_01_18  & 1)*5+(#a_01_19  & 1)*7+(#a_03_20  & 1)*7+(#a_01_21  & 1)*5+(#a_01_22  & 1)*7+(#a_01_23  & 1)*5+(#a_01_24  & 1)*7+(#a_03_25  & 1)*5+(#a_01_26  & 1)*7+(#a_03_27  & 1)*7) >=32
 
}