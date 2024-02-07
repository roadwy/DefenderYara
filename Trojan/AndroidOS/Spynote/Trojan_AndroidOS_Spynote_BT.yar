
rule Trojan_AndroidOS_Spynote_BT{
	meta:
		description = "Trojan:AndroidOS/Spynote.BT,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 53 77 4b 79 71 62 48 67 41 } //01 00  HSwKyqbHgA
		$a_01_1 = {4d 5a 6c 67 4d 69 72 4e 6d 76 } //01 00  MZlgMirNmv
		$a_01_2 = {71 77 65 72 74 79 32 31 33 34 35 68 6a 64 6e 6a 64 } //01 00  qwerty21345hjdnjd
		$a_01_3 = {37 34 65 38 64 32 30 34 36 31 38 63 38 64 36 35 61 31 39 34 36 33 61 65 62 65 62 33 36 37 30 38 } //01 00  74e8d204618c8d65a19463aebeb36708
		$a_01_4 = {37 34 65 39 64 35 33 63 39 30 63 65 36 66 31 30 39 66 37 36 66 32 61 62 66 38 36 35 32 63 31 65 } //01 00  74e9d53c90ce6f109f76f2abf8652c1e
		$a_01_5 = {37 34 66 31 31 62 31 39 38 35 31 32 36 32 37 35 } //00 00  74f11b1985126275
	condition:
		any of ($a_*)
 
}