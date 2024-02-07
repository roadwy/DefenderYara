
rule Trojan_BAT_Lokibot_DD_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {44 32 32 32 32 32 32 32 32 32 32 32 32 32 32 } //01 00  D22222222222222
		$a_81_1 = {00 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 00 } //01 00 
		$a_81_2 = {58 32 33 34 35 32 34 33 32 34 } //01 00  X234524324
		$a_81_3 = {67 6e 69 72 74 53 34 36 65 73 61 42 6d 6f 72 46 } //01 00  gnirtS46esaBmorF
		$a_81_4 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_6 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_7 = {47 65 74 54 79 70 65 } //00 00  GetType
	condition:
		any of ($a_*)
 
}