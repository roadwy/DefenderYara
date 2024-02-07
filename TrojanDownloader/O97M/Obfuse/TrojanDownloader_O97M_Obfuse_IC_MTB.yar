
rule TrojanDownloader_O97M_Obfuse_IC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.IC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 31 33 38 2e 36 38 2e 32 31 37 2e 32 33 34 2f 63 72 79 70 74 65 64 2e 65 78 65 } //01 00  http://138.68.217.234/crypted.exe
		$a_01_1 = {74 65 4d 70 5c 6c 48 63 63 2e 65 78 65 } //01 00  teMp\lHcc.exe
		$a_01_2 = {43 68 72 28 31 31 39 29 20 26 20 61 20 26 20 43 68 72 28 31 31 34 29 20 26 20 43 68 72 28 31 31 35 29 20 26 20 43 68 72 28 31 30 34 29 20 26 20 61 20 26 20 43 68 72 28 31 30 38 29 20 26 } //00 00  Chr(119) & a & Chr(114) & Chr(115) & Chr(104) & a & Chr(108) &
	condition:
		any of ($a_*)
 
}