
rule TrojanDropper_O97M_InjectorDropper_SK_MTB{
	meta:
		description = "TrojanDropper:O97M/InjectorDropper.SK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 05 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {22 2c 20 22 76 6e 70 2e 64 6c 6c 22 2c 20 22 } //01 00  ", "vnp.dll", "
		$a_01_1 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //01 00  Private Sub Document_Open()
		$a_01_2 = {64 65 6c 61 79 6d 61 69 6c 74 6f 20 3d 20 50 61 73 73 61 6e 74 2e 62 65 61 73 74 6d 6f 64 65 28 30 29 } //01 00  delaymailto = Passant.beastmode(0)
		$a_01_3 = {43 61 6c 6c 20 74 70 6c 5f 76 69 64 } //00 00  Call tpl_vid
	condition:
		any of ($a_*)
 
}