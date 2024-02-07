
rule Trojan_BAT_AgentTesla_FE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 0a 00 "
		
	strings :
		$a_81_0 = {68 69 6c 61 6c 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  hilal.Properties.Resources
		$a_81_1 = {43 6f 6e 76 65 72 74 } //01 00  Convert
		$a_81_2 = {54 6f 53 74 72 69 6e 67 } //01 00  ToString
		$a_81_3 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_81_4 = {43 6f 6e 63 61 74 } //01 00  Concat
		$a_81_5 = {47 65 74 54 79 } //01 00  GetTy
		$a_81_6 = {45 6e 74 72 79 50 } //00 00  EntryP
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_FE_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.FE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {52 65 6c 6f 61 64 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Reload.My.Resources
		$a_81_1 = {52 65 6c 6f 61 64 2e 52 65 6c 6f 61 64 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Reload.Reload.resources
		$a_81_2 = {31 31 31 31 31 2d 32 32 32 32 32 2d 32 30 30 30 31 2d 30 30 30 30 31 } //01 00  11111-22222-20001-00001
		$a_81_3 = {66 69 6c 65 3a 2f 2f 2f } //01 00  file:///
		$a_81_4 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_81_5 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_81_6 = {46 6f 72 6d 31 } //01 00  Form1
		$a_81_7 = {49 6d 61 67 65 42 6d 70 } //01 00  ImageBmp
		$a_81_8 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_9 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}