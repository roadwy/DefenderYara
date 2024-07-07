
rule TrojanDownloader_O97M_Dridex_PD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.PD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 68 65 65 74 73 28 31 29 2e 43 65 6c 6c 73 28 36 2c 20 31 29 2e 76 61 6c 75 65 20 3d 20 6a 20 26 20 6d 3a 20 6d 67 20 3d 20 22 41 75 74 22 } //1 Sheets(1).Cells(6, 1).value = j & m: mg = "Aut"
		$a_00_1 = {53 68 65 65 74 73 28 31 29 2e 43 65 6c 6c 73 28 31 2c 20 31 29 2e 4e 61 6d 65 20 3d 20 6d 67 20 26 20 22 6f 5f 69 6f 32 32 22 } //1 Sheets(1).Cells(1, 1).Name = mg & "o_io22"
		$a_00_2 = {53 68 65 65 74 73 28 31 29 2e 43 65 6c 6c 73 28 31 2c 20 31 29 2e 76 61 6c 75 65 20 3d 20 22 3d 22 20 26 20 52 65 70 6c 61 63 65 28 45 2c 20 22 5b 22 2c 20 22 4a 22 29 } //1 Sheets(1).Cells(1, 1).value = "=" & Replace(E, "[", "J")
		$a_00_3 = {75 20 3d 20 75 20 26 20 43 68 72 28 41 73 63 28 4d 69 64 28 6e 2c 20 58 2c 20 31 29 29 20 2b 20 6b 29 3a 20 4e 65 78 74 } //1 u = u & Chr(Asc(Mid(n, X, 1)) + k): Next
		$a_00_4 = {52 75 6e 20 28 6d 67 20 26 20 22 6f 5f 69 6f 32 32 22 29 } //1 Run (mg & "o_io22")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}