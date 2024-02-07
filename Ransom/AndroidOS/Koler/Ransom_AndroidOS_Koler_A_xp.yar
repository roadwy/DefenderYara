
rule Ransom_AndroidOS_Koler_A_xp{
	meta:
		description = "Ransom:AndroidOS/Koler.A!xp,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {3a 2f 2f 68 6f 74 67 72 61 64 65 72 70 6f 72 6e 70 72 69 76 61 74 65 2e 65 75 } //01 00  ://hotgraderpornprivate.eu
		$a_00_1 = {46 42 49 5f 41 6e 74 69 2d 50 69 72 61 63 79 5f 57 61 72 6e 69 6e 67 } //01 00  FBI_Anti-Piracy_Warning
		$a_00_2 = {79 6f 75 72 20 44 65 76 69 63 65 20 68 61 73 20 62 65 65 6e 20 6c 6f 63 6b 65 64 } //00 00  your Device has been locked
	condition:
		any of ($a_*)
 
}