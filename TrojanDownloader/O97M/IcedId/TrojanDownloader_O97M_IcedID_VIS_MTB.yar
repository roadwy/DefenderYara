
rule TrojanDownloader_O97M_IcedID_VIS_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 20 22 5c 6d 31 2e 78 73 6c } //01 00  & "\m1.xsl
		$a_01_1 = {26 20 22 5c 6d 31 2e 63 6f 6d } //01 00  & "\m1.com
		$a_01_2 = {72 75 6e 20 61 33 38 55 62 35 20 26 20 61 52 6c 4d 79 78 28 22 63 6f 6d 6d 65 6e 74 73 22 29 20 26 20 61 6d 45 32 61 6b 20 26 20 61 51 78 6f 33 42 20 26 20 61 6d 45 32 61 6b } //01 00  run a38Ub5 & aRlMyx("comments") & amE2ak & aQxo3B & amE2ak
		$a_01_3 = {46 69 6c 65 43 6f 70 79 } //00 00  FileCopy
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_IcedID_VIS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/IcedID.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 70 6c 69 74 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 2c 20 22 78 22 29 } //01 00  Split(ActiveDocument.Range.Text, "x")
		$a_03_1 = {26 20 22 6d 64 61 74 61 5c 90 02 20 2e 68 22 20 26 90 00 } //01 00 
		$a_03_2 = {53 68 65 6c 6c 90 02 ff 28 22 65 78 70 6c 6f 72 65 72 20 22 29 90 00 } //01 00 
		$a_03_3 = {50 72 69 6e 74 20 23 31 2c 20 90 02 20 43 6c 6f 73 65 20 23 31 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //01 00 
		$a_01_4 = {6f 75 74 20 26 20 43 68 72 28 61 72 72 28 63 6e 74 29 20 58 6f 72 20 31 30 30 29 } //00 00  out & Chr(arr(cnt) Xor 100)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_IcedID_VIS_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/IcedID.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 70 74 69 6f 6e 61 6c 20 63 75 72 72 49 6e 74 65 67 65 72 54 72 75 73 74 20 3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 22 2c 20 4f 70 74 69 6f 6e 61 6c 20 57 53 65 74 50 6f 69 6e 74 65 72 20 3d 20 22 61 22 29 } //01 00  Optional currIntegerTrust = "c:\program", Optional WSetPointer = "a")
		$a_01_1 = {26 20 22 64 61 74 61 5c 61 72 72 56 61 6c 54 72 75 73 74 2e 68 74 22 20 26 } //01 00  & "data\arrValTrust.ht" &
		$a_01_2 = {6f 75 74 20 26 20 43 68 72 28 61 72 72 28 63 6e 74 29 20 58 6f 72 20 31 30 29 } //01 00  out & Chr(arr(cnt) Xor 10)
		$a_01_3 = {53 68 65 6c 6c 28 68 65 61 64 65 72 49 6e 64 28 22 63 3a 5c 5c 77 69 6e 64 6f 77 73 5c 5c 65 78 70 6c 6f 72 65 72 20 22 29 } //00 00  Shell(headerInd("c:\\windows\\explorer ")
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_IcedID_VIS_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/IcedID.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 69 73 74 42 6f 78 31 2e 41 64 64 49 74 65 6d 20 28 22 3a 2f 2f 64 65 74 74 61 67 6c 2e 6e 65 74 2f 22 20 2b 20 4d 65 6d 53 65 6c 65 63 74 28 29 29 } //01 00  ListBox1.AddItem ("://dettagl.net/" + MemSelect())
		$a_01_1 = {56 61 72 44 61 74 61 62 61 73 65 2e 57 72 69 74 65 } //01 00  VarDatabase.Write
		$a_01_2 = {56 61 72 44 61 74 61 62 61 73 65 2e 53 61 76 65 54 6f 46 69 6c 65 } //01 00  VarDatabase.SaveToFile
		$a_01_3 = {53 68 65 6c 6c 25 20 28 52 65 70 6f 43 6f 6e 76 65 72 74 52 69 67 68 74 20 2b 20 22 20 22 20 26 } //01 00  Shell% (RepoConvertRight + " " &
		$a_01_4 = {43 3a 5c 75 73 65 72 73 5c 50 75 62 6c 69 63 5c 22 20 2b 20 4d 65 6d 53 65 6c 65 63 74 28 29 } //01 00  C:\users\Public\" + MemSelect()
		$a_01_5 = {3d 20 43 53 74 72 28 49 6e 74 28 39 39 39 39 39 39 20 2a 20 52 6e 64 29 20 2b 20 31 29 20 2b 20 22 2e 6a 70 67 22 } //00 00  = CStr(Int(999999 * Rnd) + 1) + ".jpg"
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_IcedID_VIS_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/IcedID.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 43 53 74 72 28 49 6e 74 28 39 39 39 39 39 39 20 2a 20 52 6e 64 29 20 2b 20 31 29 20 2b 20 22 2e 6a 70 67 22 } //01 00  = CStr(Int(999999 * Rnd) + 1) + ".jpg"
		$a_01_1 = {4c 69 73 74 42 6f 78 31 2e 41 64 64 49 74 65 6d 20 28 22 3a 2f 2f 63 6f 6e 64 69 7a 69 6f 6e 69 2e 6e 65 74 2f 22 20 2b 20 52 65 73 70 6f 6e 73 65 4c 65 6e 53 65 6c 65 63 74 28 29 29 } //01 00  ListBox1.AddItem ("://condizioni.net/" + ResponseLenSelect())
		$a_01_2 = {43 3a 5c 75 73 65 72 73 5c 50 75 62 6c 69 63 5c 22 20 2b 20 52 65 73 70 6f 6e 73 65 4c 65 6e 53 65 6c 65 63 74 28 29 } //01 00  C:\users\Public\" + ResponseLenSelect()
		$a_01_3 = {42 75 66 66 65 72 36 34 50 6f 69 6e 74 65 72 2e 57 72 69 74 65 } //01 00  Buffer64Pointer.Write
		$a_01_4 = {42 75 66 66 65 72 36 34 50 6f 69 6e 74 65 72 2e 53 61 76 65 54 6f 46 69 6c 65 } //01 00  Buffer64Pointer.SaveToFile
		$a_01_5 = {53 68 65 6c 6c 25 20 28 43 6f 75 6e 74 65 72 50 72 6f 63 43 6f 6e 73 74 20 2b 20 22 20 22 20 26 } //00 00  Shell% (CounterProcConst + " " &
	condition:
		any of ($a_*)
 
}