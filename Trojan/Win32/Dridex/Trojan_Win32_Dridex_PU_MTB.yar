
rule Trojan_Win32_Dridex_PU_MTB{
	meta:
		description = "Trojan:Win32/Dridex.PU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0b 00 00 01 00 "
		
	strings :
		$a_81_0 = {44 45 78 72 6c 6f 72 65 72 69 6e 63 6c 75 64 65 64 47 72 6f 67 6c 65 57 45 } //01 00  DExrlorerincludedGrogleWE
		$a_81_1 = {74 68 61 74 50 6e 65 77 } //01 00  thatPnew
		$a_81_2 = {69 61 6c 6c 6f 77 73 6c 61 74 65 72 } //01 00  iallowslater
		$a_81_3 = {66 6f 72 74 6f 46 6f 74 68 72 72 64 46 6c 61 73 68 73 68 61 72 65 } //01 00  fortoFothrrdFlashshare
		$a_81_4 = {41 64 62 6c 6f 63 6b 66 65 61 74 75 72 65 73 66 33 36 25 75 34 42 4b 41 } //01 00  Adblockfeaturesf36%u4BKA
		$a_81_5 = {62 72 6f 77 73 65 72 75 6e 64 65 72 46 65 62 72 75 61 72 79 6d 74 65 73 74 62 } //01 00  browserunderFebruarymtestb
		$a_81_6 = {42 45 63 6f 6e 6f 6d 69 63 6d 6f 64 65 74 79 70 65 73 } //01 00  BEconomicmodetypes
		$a_81_7 = {6d 61 72 6b 47 6f 6f 67 6c 65 5a 6c 6f 67 73 61 } //01 00  markGoogleZlogsa
		$a_81_8 = {43 68 72 6f 6d 65 63 6f 72 65 6c 65 61 73 65 } //01 00  Chromecorelease
		$a_81_9 = {41 64 64 55 73 65 72 73 54 6f 45 6e 63 72 79 70 74 65 64 46 69 6c 65 } //0a 00  AddUsersToEncryptedFile
		$a_02_10 = {21 c0 8b 4d 90 01 01 8b 90 02 06 89 90 02 06 8a 90 02 02 0f 90 02 07 29 90 01 01 8b 90 02 03 89 90 02 02 89 90 02 03 e8 90 02 04 8b 90 02 03 01 90 01 01 88 90 02 08 8b 90 02 02 8a 90 02 06 8b 90 02 06 88 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}