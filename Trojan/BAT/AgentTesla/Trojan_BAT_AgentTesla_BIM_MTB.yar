
rule Trojan_BAT_AgentTesla_BIM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 0a 00 00 0a 00 "
		
	strings :
		$a_00_0 = {75 00 72 00 75 00 47 00 00 11 50 00 6f 00 73 00 69 00 74 00 69 00 6f 00 6e 00 00 0d 4c 00 65 00 6e 00 67 00 74 00 68 } //0a 00 
		$a_81_1 = {49 49 49 49 49 49 49 49 49 49 49 49 49 2e 4c 2e 53 79 73 74 65 6d 2e 49 4f 2e 44 47 49 50 } //01 00  IIIIIIIIIIIII.L.System.IO.DGIP
		$a_81_2 = {41 64 64 45 6c 65 6d 65 6e 74 73 } //01 00  AddElements
		$a_81_3 = {54 61 73 6b 43 61 6e 63 65 6c 65 64 45 78 63 65 70 74 69 6f 6e } //01 00  TaskCanceledException
		$a_81_4 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_81_5 = {49 6e 76 6f 6b 65 4d 65 74 68 6f 64 } //01 00  InvokeMethod
		$a_81_6 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_81_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_8 = {49 53 65 63 74 69 6f 6e 45 6e 74 72 79 } //01 00  ISectionEntry
		$a_81_9 = {67 65 74 41 76 65 72 61 67 65 } //00 00  getAverage
	condition:
		any of ($a_*)
 
}