
rule TrojanDownloader_Linux_Hagof_gen_A{
	meta:
		description = "TrojanDownloader:Linux/Hagof.gen!A,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 66 20 31 20 3d 20 31 20 54 68 65 6e 3a 20 6d 63 61 66 65 65 20 3d 20 45 6e 76 69 72 6f 6e 28 6d 63 61 66 65 65 29 } //01 00  If 1 = 1 Then: mcafee = Environ(mcafee)
		$a_01_1 = {49 66 20 31 20 3d 20 31 20 54 68 65 6e 3a 20 41 44 53 2e 57 72 69 74 65 20 58 4d 4c 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 } //01 00  If 1 = 1 Then: ADS.Write XML.responseBody
		$a_01_2 = {49 66 20 31 20 3d 20 31 20 54 68 65 6e 3a 20 57 69 6b 69 70 65 64 69 61 20 3d 20 22 68 22 20 26 20 22 74 74 22 20 26 20 5f } //01 00  If 1 = 1 Then: Wikipedia = "h" & "tt" & _
		$a_01_3 = {49 66 20 31 20 3d 20 31 20 54 68 65 6e 3a 20 53 68 65 6c 6c 20 57 69 6b 69 70 65 64 69 61 28 22 53 52 22 29 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 } //00 00  If 1 = 1 Then: Shell Wikipedia("SR"), vbNormalFocus
		$a_00_4 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}