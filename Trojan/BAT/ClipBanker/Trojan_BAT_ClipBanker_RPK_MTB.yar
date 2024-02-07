
rule Trojan_BAT_ClipBanker_RPK_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6c 69 70 70 65 72 2e 65 78 65 } //01 00  Clipper.exe
		$a_01_1 = {47 65 74 54 65 6d 70 50 61 74 68 } //01 00  GetTempPath
		$a_01_2 = {53 70 65 63 69 61 6c 46 6f 6c 64 65 72 } //01 00  SpecialFolder
		$a_01_3 = {63 57 61 6c 6c 65 74 73 } //01 00  cWallets
		$a_01_4 = {43 68 65 63 6b 4d 75 74 65 78 } //01 00  CheckMutex
		$a_01_5 = {63 53 74 61 72 74 55 70 } //01 00  cStartUp
		$a_01_6 = {64 57 61 6c 6c 65 74 73 } //01 00  dWallets
		$a_01_7 = {45 00 37 00 77 00 44 00 6d 00 54 00 69 00 30 00 52 00 35 00 34 00 4d 00 61 00 4f 00 50 00 72 00 67 00 77 00 54 00 37 00 37 00 30 00 4e 00 33 00 32 00 } //00 00  E7wDmTi0R54MaOPrgwT770N32
	condition:
		any of ($a_*)
 
}