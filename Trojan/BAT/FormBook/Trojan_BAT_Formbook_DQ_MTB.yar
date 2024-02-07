
rule Trojan_BAT_Formbook_DQ_MTB{
	meta:
		description = "Trojan:BAT/Formbook.DQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 35 34 61 62 33 31 63 64 2d 31 35 32 36 2d 34 36 61 39 2d 62 64 62 34 2d 61 37 39 36 34 37 32 38 31 32 39 35 } //01 00  $54ab31cd-1526-46a9-bdb4-a79647281295
		$a_81_1 = {4d 69 6c 6b 5f 44 61 69 72 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Milk_Dairy.Resources
		$a_81_2 = {43 6f 6c 6c 65 63 74 4d 69 6c 6b } //01 00  CollectMilk
		$a_81_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_81_4 = {47 65 74 52 65 73 6f 75 72 63 65 53 74 72 69 6e 67 } //01 00  GetResourceString
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //00 00  DebuggerBrowsableState
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Formbook_DQ_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.DQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 65 66 65 62 38 38 36 66 2d 32 39 32 36 2d 34 39 37 36 2d 61 37 36 61 2d 31 63 34 39 36 64 61 36 61 32 32 64 } //01 00  $efeb886f-2926-4976-a76a-1c496da6a22d
		$a_81_1 = {52 65 6e 64 61 5f 4c 6f 6e 6e 69 65 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Renda_Lonnie.My.Resources
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_3 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_4 = {77 72 69 74 65 54 6f 46 69 6c 65 } //01 00  writeToFile
		$a_81_5 = {49 6e 74 65 72 6c 6f 63 6b 65 64 } //00 00  Interlocked
	condition:
		any of ($a_*)
 
}