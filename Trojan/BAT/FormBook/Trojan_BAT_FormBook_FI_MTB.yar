
rule Trojan_BAT_FormBook_FI_MTB{
	meta:
		description = "Trojan:BAT/FormBook.FI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 0e 00 00 14 00 "
		
	strings :
		$a_81_0 = {75 79 33 32 65 31 32 33 } //14 00  uy32e123
		$a_81_1 = {73 64 66 73 64 66 73 61 64 65 61 } //14 00  sdfsdfsadea
		$a_81_2 = {67 73 64 66 61 73 64 66 61 73 } //14 00  gsdfasdfas
		$a_81_3 = {64 69 6b 33 69 61 6f 77 64 61 73 64 } //14 00  dik3iaowdasd
		$a_81_4 = {6d 6b 61 73 6b 64 61 64 61 73 } //01 00  mkaskdadas
		$a_81_5 = {4e 6f 6e 20 4f 62 66 75 73 63 61 74 65 64 } //01 00  Non Obfuscated
		$a_81_6 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_81_7 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_81_8 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_81_9 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_81_10 = {52 65 73 6f 6c 76 65 53 69 67 6e 61 74 75 72 65 } //01 00  ResolveSignature
		$a_81_11 = {4c 6f 61 64 4d 6f 64 75 6c 65 } //01 00  LoadModule
		$a_81_12 = {43 6f 6e 76 65 72 74 } //01 00  Convert
		$a_81_13 = {47 65 74 54 79 70 65 73 } //00 00  GetTypes
	condition:
		any of ($a_*)
 
}