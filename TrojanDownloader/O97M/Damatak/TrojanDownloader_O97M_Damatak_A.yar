
rule TrojanDownloader_O97M_Damatak_A{
	meta:
		description = "TrojanDownloader:O97M/Damatak.A,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 72 61 74 65 20 3d 20 61 6c 6c 65 72 67 79 28 42 79 56 61 6c 20 74 72 61 6e 73 64 75 63 65 72 2c 20 61 72 69 73 74 6f 6e 2c 20 42 79 56 61 6c 20 6f 69 6c 73 65 65 64 2c 20 66 72 61 6e 63 74 69 72 65 75 72 2c 20 42 79 56 61 6c 20 72 65 76 65 72 65 6e 74 69 61 6c 2c 20 42 79 56 61 6c 20 63 6f 6d 70 6f 6e 65 6e 74 29 } //01 00  crate = allergy(ByVal transducer, ariston, ByVal oilseed, franctireur, ByVal reverential, ByVal component)
		$a_01_1 = {61 67 61 72 69 63 20 3d 20 67 65 6c 61 73 6d 61 67 72 28 42 79 56 61 6c 20 64 69 6f 64 65 2c 20 62 6f 77 69 6e 67 2c 20 42 79 56 61 6c 20 63 72 6f 73 73 72 6f 61 64 2c 20 66 65 72 6e 6c 69 6b 65 2c 20 42 79 56 61 6c 20 6d 68 2c 20 42 79 56 61 6c 20 6d 65 6c 6f 64 72 61 6d 61 74 69 63 61 6c 6c 79 29 } //00 00  agaric = gelasmagr(ByVal diode, bowing, ByVal crossroad, fernlike, ByVal mh, ByVal melodramatically)
	condition:
		any of ($a_*)
 
}