
rule TrojanDownloader_O97M_Qakbot_TADE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.TADE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 65 74 73 28 22 4e 6f 69 65 65 74 66 64 68 67 22 29 2e 52 61 6e 67 65 28 22 48 32 34 22 29 20 3d 20 64 67 64 67 65 72 77 72 68 20 26 20 22 70 22 20 26 20 22 3a 2f 22 20 26 20 22 2f 31 39 30 2e 31 34 2e 33 37 2e 32 34 34 } //1 Sheets("Noieetfdhg").Range("H24") = dgdgerwrh & "p" & ":/" & "/190.14.37.244
		$a_01_1 = {53 68 65 65 74 73 28 22 4e 6f 69 65 65 74 66 64 68 67 22 29 2e 52 61 6e 67 65 28 22 48 32 35 22 29 20 3d 20 64 67 64 67 65 72 77 72 68 20 26 20 22 70 22 20 26 20 22 3a 2f 22 20 26 20 22 2f 31 39 34 2e 33 36 2e 31 39 31 2e 33 35 } //1 Sheets("Noieetfdhg").Range("H25") = dgdgerwrh & "p" & ":/" & "/194.36.191.35
		$a_01_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 53 68 65 65 74 73 28 22 4e 6f 69 65 65 74 66 64 68 67 22 29 2e 52 61 6e 67 65 28 22 48 33 22 29 } //1 Application.Run Sheets("Noieetfdhg").Range("H3")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}