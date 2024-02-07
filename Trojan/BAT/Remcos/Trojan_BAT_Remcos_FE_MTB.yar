
rule Trojan_BAT_Remcos_FE_MTB{
	meta:
		description = "Trojan:BAT/Remcos.FE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {56 61 5a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 41 } //01 00  VaZzzzzzzzzzzA
		$a_81_1 = {52 75 6e 6e 6e 6e 6e } //01 00  Runnnnn
		$a_81_2 = {31 32 33 63 75 74 65 } //01 00  123cute
		$a_81_3 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_5 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_6 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_7 = {52 65 70 6c 61 63 65 } //00 00  Replace
	condition:
		any of ($a_*)
 
}