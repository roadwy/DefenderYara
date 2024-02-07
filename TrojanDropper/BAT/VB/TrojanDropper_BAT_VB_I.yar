
rule TrojanDropper_BAT_VB_I{
	meta:
		description = "TrojanDropper:BAT/VB.I,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {50 6f 6c 79 58 6f 72 62 79 4d 69 68 61 72 62 69 44 6f 6e 6f } //03 00  PolyXorbyMiharbiDono
		$a_01_1 = {50 6f 6c 79 44 65 43 72 79 70 74 } //00 00  PolyDeCrypt
	condition:
		any of ($a_*)
 
}