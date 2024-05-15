
rule Trojan_Win32_WitchSyndrome_C_dha{
	meta:
		description = "Trojan:Win32/WitchSyndrome.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 52 52 46 45 52 57 45 52 51 57 45 41 52 46 41 53 46 44 53 41 44 52 54 52 57 45 46 53 44 46 64 66 73 61 34 35 34 33 35 34 33 35 36 74 66 64 73 67 64 73 7a 67 66 73 64 21 33 32 34 33 35 63 } //01 00  CRRFERWERQWEARFASFDSADRTRWEFSDFdfsa454354356tfdsgdszgfsd!32435c
		$a_81_1 = {53 65 63 2d 46 65 74 63 68 2d 41 54 48 } //01 00  Sec-Fetch-ATH
		$a_81_2 = {45 46 34 35 34 74 66 40 33 33 32 35 34 79 63 33 23 } //01 00  EF454tf@33254yc3#
		$a_81_3 = {53 65 63 2d 46 65 74 63 68 2d 43 4e } //01 00  Sec-Fetch-CN
		$a_81_4 = {53 65 63 2d 46 65 74 63 68 2d 53 51 } //01 00  Sec-Fetch-SQ
		$a_01_5 = {53 71 6c 44 61 74 61 52 65 61 64 65 72 } //01 00  SqlDataReader
		$a_01_6 = {53 71 6c 43 6f 6d 6d 61 6e 64 } //01 00  SqlCommand
		$a_01_7 = {73 65 74 5f 43 6f 6e 6e 65 63 74 69 6f 6e 53 74 72 69 6e 67 } //01 00  set_ConnectionString
		$a_01_8 = {53 79 73 74 65 6d 2e 44 61 74 61 2e 53 71 6c 43 6c 69 65 6e 74 } //00 00  System.Data.SqlClient
	condition:
		any of ($a_*)
 
}