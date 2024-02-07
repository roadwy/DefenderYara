
rule TrojanDownloader_O97M_Dokgirat_A{
	meta:
		description = "TrojanDownloader:O97M/Dokgirat.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 32 31 6b 20 4c 6d 56 34 5a 51 3d 3d } //01 00  Y21k LmV4ZQ==
		$a_01_1 = {4c 32 4d 67 63 33 52 68 63 6e 51 3d } //01 00  L2Mgc3RhcnQ=
		$a_01_2 = {61 32 31 69 63 6a 45 75 62 6d 6c 30 5a 58 4e 69 63 6a 45 75 62 33 4a 6e } //01 00  a21icjEubml0ZXNicjEub3Jn
		$a_01_3 = {4c 31 56 7a 5a 58 4a 47 61 57 78 6c 63 79 39 47 61 57 78 6c 4c 32 6c 74 59 57 64 6c 4c 32 68 76 62 57 55 75 61 48 52 74 62 41 3d 3d } //00 00  L1VzZXJGaWxlcy9GaWxlL2ltYWdlL2hvbWUuaHRtbA==
	condition:
		any of ($a_*)
 
}