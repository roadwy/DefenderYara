
rule TrojanDownloader_O97M_Adnel_F{
	meta:
		description = "TrojanDownloader:O97M/Adnel.F,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 3d 20 43 68 72 28 31 30 34 29 20 26 20 43 68 72 28 31 31 36 29 20 26 20 22 3d 22 20 26 20 43 68 72 28 31 31 36 29 20 26 20 43 68 72 28 31 31 32 29 20 26 20 43 68 72 28 35 38 29 20 26 20 22 2f 22 20 26 20 22 3c 2f 22 20 26 20 } //00 00   = Chr(104) & Chr(116) & "=" & Chr(116) & Chr(112) & Chr(58) & "/" & "</" & 
	condition:
		any of ($a_*)
 
}