
rule TrojanDownloader_O97M_Ursnif_SS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 73 65 74 52 65 71 75 65 73 74 48 65 61 64 65 72 20 22 65 74 61 67 22 2c 20 22 66 65 74 63 68 22 } //1 .setRequestHeader "etag", "fetch"
		$a_01_1 = {3d 20 52 65 70 6c 61 63 65 28 6c 6f 72 63 61 2c 20 63 65 73 73 69 6f 6e 65 2c 20 22 22 29 } //1 = Replace(lorca, cessione, "")
		$a_03_2 = {4d 73 67 42 6f 78 20 28 4c 65 6e 28 [0-1f] 28 28 [0-0f] 28 22 90 05 02 05 28 30 2d 39 29 68 90 05 02 05 28 30 2d 39 29 74 [0-02] 74 70 [0-02] 73 3a [0-02] 2f 2f [0-02] 77 68 61 74 73 77 69 74 [0-02] 2e 63 [0-03] 6f 6d 22 29 29 29 29 20 2d 20 [0-04] 20 2d 20 [0-02] 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Ursnif_SS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 6a 6a 20 3d 20 77 2e 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 28 30 20 2b 20 6a 29 [0-03] 41 6a 6a 20 3d 20 41 6a 6a 20 26 20 22 5c 22 20 26 20 41 62 73 28 41 70 70 6c 69 63 61 74 69 6f 6e 2e 57 69 6e 64 6f 77 53 74 61 74 65 29 20 26 20 22 2e 22 [0-03] 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
		$a_01_1 = {43 61 6c 6c 20 53 68 65 6c 6c 28 28 4a 4a 4a 28 6a 20 2d 20 31 29 20 26 20 61 29 29 } //1 Call Shell((JJJ(j - 1) & a))
		$a_01_2 = {61 20 3d 20 61 20 26 20 4d 69 64 28 6b 2e 43 65 6c 6c 73 28 31 2c 20 31 29 2c 20 4c 65 6e 28 6b 2e 43 65 6c 6c 73 28 31 2c 20 6a 29 29 20 2b 20 31 2c 20 6a 29 } //1 a = a & Mid(k.Cells(1, 1), Len(k.Cells(1, j)) + 1, j)
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}