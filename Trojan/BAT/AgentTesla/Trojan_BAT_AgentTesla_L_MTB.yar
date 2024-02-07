
rule Trojan_BAT_AgentTesla_L_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {47 65 74 52 75 6e 6e 69 6e 67 44 6f 63 75 6d 65 6e 74 73 45 6e 75 6d } //01 00  GetRunningDocumentsEnum
		$a_00_1 = {53 79 73 74 65 6d 2e 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e } //01 00  System.IO.Compression
		$a_00_2 = {49 45 6e 75 6d 52 75 6e 6e 69 6e 67 44 6f 63 75 6d 65 6e 74 73 } //01 00  IEnumRunningDocuments
		$a_00_3 = {49 50 41 64 64 72 65 73 73 } //01 00  IPAddress
		$a_01_4 = {28 15 00 00 06 72 01 00 00 70 28 16 00 00 06 72 05 00 00 70 28 46 00 00 0a 28 47 00 00 0a 28 17 00 00 06 28 48 00 00 0a 20 02 00 00 00 8d 07 00 00 01 25 20 01 00 00 00 20 01 00 00 00 8d 07 00 00 01 25 20 00 00 00 00 28 49 00 00 0a a2 a2 28 4a 00 00 0a 26 } //00 00 
	condition:
		any of ($a_*)
 
}