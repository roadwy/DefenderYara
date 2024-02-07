
rule TrojanDropper_O97M_SilverMob_A_dha{
	meta:
		description = "TrojanDropper:O97M/SilverMob.A!dha,SIGNATURE_TYPE_MACROHSTR_EXT,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {28 31 29 20 3d 20 22 41 41 42 44 37 37 45 37 45 34 45 37 45 37 45 37 45 33 45 37 45 37 } //01 00  (1) = "AABD77E7E4E7E7E7E3E7E7
		$a_00_1 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //01 00  Sub AutoOpen()
		$a_00_2 = {6c 69 76 65 4f 6e } //01 00  liveOn
		$a_00_3 = {73 76 63 68 6f 73 74 2e 65 78 65 } //00 00  svchost.exe
	condition:
		any of ($a_*)
 
}
rule TrojanDropper_O97M_SilverMob_A_dha_2{
	meta:
		description = "TrojanDropper:O97M/SilverMob.A!dha,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 68 72 28 34 36 20 2b 20 28 41 73 63 28 } //01 00  Chr(46 + (Asc(
		$a_00_1 = {29 20 2d 20 34 36 20 2d 20 32 30 20 2b 20 28 31 32 32 20 2d 20 34 36 29 29 20 4d 6f 64 20 28 31 32 32 20 2d 20 34 36 29 29 } //01 00  ) - 46 - 20 + (122 - 46)) Mod (122 - 46))
		$a_00_2 = {2b 20 43 68 72 28 41 73 63 28 4d 69 64 24 28 } //01 00  + Chr(Asc(Mid$(
		$a_00_3 = {6f 62 6a 2e 52 75 6e 20 66 69 6c 65 6e 61 6d 65 2c 20 31 2c 20 46 61 6c 73 65 } //00 00  obj.Run filename, 1, False
	condition:
		any of ($a_*)
 
}