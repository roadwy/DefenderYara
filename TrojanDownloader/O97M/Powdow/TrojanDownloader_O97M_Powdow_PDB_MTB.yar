
rule TrojanDownloader_O97M_Powdow_PDB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PDB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {28 6e 45 77 2d 6f 42 60 6a 65 63 54 20 4e 65 74 2e 57 65 62 63 4c 60 49 45 4e 74 29 } //1 (nEw-oB`jecT Net.WebcL`IENt)
		$a_01_1 = {28 27 44 6f 77 6e 27 2b 27 6c 6f 61 64 46 69 6c 65 27 29 } //1 ('Down'+'loadFile')
		$a_01_2 = {49 6e 76 6f 6b 65 22 28 27 68 74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 78 64 79 61 37 6a 36 27 2c 27 70 64 2e 62 61 74 27 29 } //1 Invoke"('https://tinyurl.com/yxdya7j6','pd.bat')
		$a_01_3 = {49 6e 76 6f 6b 65 22 22 28 27 68 74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 32 33 70 76 34 71 74 27 2c 27 70 64 2e 62 61 74 27 29 22 29 } //1 Invoke""('https://tinyurl.com/y23pv4qt','pd.bat')")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_PDB_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PDB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 67 42 70 41 43 41 41 49 67 42 6f 41 48 51 41 64 41 42 77 41 44 6f 41 4c 77 41 76 41 44 55 41 4c 67 41 78 41 44 67 41 4d 51 41 75 63 41 43 41 44 67 41 4d 41 41 75 41 44 45 41 4d 67 41 35 41 43 38 41 61 51 42 74 41 47 45 41 5a 77 42 6c 41 48 4d 41 4c 77 42 68 41 47 34 41 64 41 63 41 43 42 70 41 48 41 41 62 41 42 68 41 47 34 41 5a 51 41 75 41 48 41 41 62 67 42 6e 41 43 49 41 49 41 41 74 41 45 38 41 64 51 42 30 41 45 59 41 61 51 42 73 41 47 55 41 49 41 63 41 43 41 69 41 45 4d 41 4f 67 42 } //1 cgBpACAAIgBoAHQAdABwADoALwAvADUALgAxADgAMQAucACADgAMAAuADEAMgA5AC8AaQBtAGEAZwBlAHMALwBhAG4AdAcACBpAHAAbABhAG4AZQAuAHAAbgBnACIAIAAtAE8AdQB0AEYAaQBsAGUAIAcACAiAEMAOgB
		$a_01_1 = {26 20 73 74 61 72 74 20 2f 42 20 63 41 43 43 63 41 43 3a 63 41 43 5c 50 63 41 43 72 6f 63 41 43 67 72 63 41 43 61 6d 63 41 43 44 63 41 43 61 74 63 41 43 61 5c 64 66 63 41 43 6c 65 2e 62 63 41 43 61 63 41 43 74 } //1 & start /B cACCcAC:cAC\PcACrocACgrcACamcACDcACatcACa\dfcACle.bcACacACt
		$a_01_2 = {77 65 72 20 3d 20 53 68 65 6c 6c 28 77 6b 6a 68 2c 20 30 29 } //1 wer = Shell(wkjh, 0)
		$a_01_3 = {72 68 71 77 6f 65 6c 68 73 6c 64 20 3d 20 52 65 70 6c 61 63 65 28 6a 6c 76 66 64 2c 20 62 78 63 6a 2c 20 22 22 29 } //1 rhqwoelhsld = Replace(jlvfd, bxcj, "")
		$a_01_4 = {66 6f 6a 6e 20 3d 20 65 72 74 6a 77 6c 6b 66 6a 28 30 2c 20 22 22 2c 20 22 22 2c 20 30 2c 20 30 29 } //1 fojn = ertjwlkfj(0, "", "", 0, 0)
		$a_01_5 = {4d 73 67 42 6f 78 20 22 71 33 34 22 } //1 MsgBox "q34"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}