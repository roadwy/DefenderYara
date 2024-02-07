
rule Trojan_BAT_AgentTesla_BQF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BQF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {06 20 00 01 00 00 6f 90 01 03 0a 00 06 20 80 00 00 00 6f 90 01 03 0a 00 7e 90 01 03 04 7e 90 01 03 04 20 e8 03 00 00 73 90 01 03 0a 0b 06 07 06 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 00 06 07 06 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 00 06 17 6f 90 00 } //01 00 
		$a_81_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //01 00  GetExecutingAssembly
		$a_81_3 = {49 6e 76 6f 6b 65 4d 65 74 68 6f 64 } //01 00  InvokeMethod
		$a_81_4 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //00 00  ClassLibrary
	condition:
		any of ($a_*)
 
}