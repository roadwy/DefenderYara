
rule Trojan_BAT_Stealer_AN_MTB{
	meta:
		description = "Trojan:BAT/Stealer.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {01 57 d4 02 fc c9 03 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 2d 00 00 00 0b 00 00 00 2b } //01 00 
		$a_01_1 = {43 6f 6e 76 65 72 74 } //01 00  Convert
		$a_01_2 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_01_3 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_01_4 = {52 65 73 6f 6c 76 65 45 76 65 6e 74 48 61 6e 64 6c 65 72 } //01 00  ResolveEventHandler
		$a_01_5 = {61 64 64 5f 41 73 73 65 6d 62 6c 79 52 65 73 6f 6c 76 65 } //00 00  add_AssemblyResolve
	condition:
		any of ($a_*)
 
}