
rule Trojan_BAT_ElysiumStealer_DG_MTB{
	meta:
		description = "Trojan:BAT/ElysiumStealer.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {66 64 73 61 73 61 73 61 61 } //01 00  fdsasasaa
		$a_81_1 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_81_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_81_3 = {44 65 63 6f 6d 70 72 65 73 73 } //01 00  Decompress
		$a_81_4 = {44 65 63 72 79 70 74 } //01 00  Decrypt
		$a_81_5 = {52 65 76 65 72 73 65 44 65 63 6f 64 65 } //01 00  ReverseDecode
		$a_81_6 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_81_7 = {43 61 72 61 6d 65 6c 65 } //00 00  Caramele
	condition:
		any of ($a_*)
 
}