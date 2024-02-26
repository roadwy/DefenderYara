
rule Trojan_BAT_AgentTesla_PREY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PREY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {57 72 69 74 65 50 61 72 73 65 72 } //01 00  WriteParser
		$a_81_1 = {43 61 6c 6c 50 61 72 73 65 72 } //01 00  CallParser
		$a_81_2 = {54 6f 53 74 72 69 6e 67 } //01 00  ToString
		$a_81_3 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_81_4 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_81_5 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_81_6 = {43 61 6c 6c 44 65 73 63 72 69 70 74 6f 72 } //01 00  CallDescriptor
		$a_81_7 = {24 32 31 30 63 37 33 34 36 2d 37 35 35 38 2d 34 39 66 36 2d 39 31 32 31 2d 38 30 63 30 36 32 33 31 62 61 33 38 } //01 00  $210c7346-7558-49f6-9121-80c06231ba38
		$a_81_8 = {46 69 6c 6c 4d 61 70 70 65 72 } //01 00  FillMapper
		$a_81_9 = {3a 2f 2f 33 38 2e 32 35 35 2e 34 33 2e 32 33 2f 64 63 64 2e 76 64 66 } //00 00  ://38.255.43.23/dcd.vdf
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_PREY_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.PREY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0c 00 00 01 00 "
		
	strings :
		$a_81_0 = {53 65 74 75 70 46 69 65 6c 64 } //01 00  SetupField
		$a_81_1 = {4c 69 73 74 46 69 65 6c 64 } //01 00  ListField
		$a_81_2 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //01 00  GetExportedTypes
		$a_81_3 = {52 65 67 69 73 74 65 72 46 69 65 6c 64 } //01 00  RegisterField
		$a_81_4 = {52 65 76 65 72 74 48 65 6c 70 65 72 } //01 00  RevertHelper
		$a_81_5 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_81_6 = {54 6f 53 74 72 69 6e 67 } //01 00  ToString
		$a_81_7 = {47 65 74 53 74 72 69 6e 67 } //01 00  GetString
		$a_81_8 = {50 44 46 65 73 63 61 70 65 20 44 65 73 6b 74 6f 70 } //01 00  PDFescape Desktop
		$a_81_9 = {24 65 31 37 63 61 32 64 34 2d 61 33 33 33 2d 34 38 61 36 2d 39 34 62 31 2d 30 33 64 38 35 63 65 62 30 38 37 36 } //01 00  $e17ca2d4-a333-48a6-94b1-03d85ceb0876
		$a_03_10 = {2f 00 2f 00 38 00 32 00 2e 00 31 00 31 00 38 00 2e 00 32 00 31 00 2e 00 36 00 39 00 2f 00 79 00 69 00 79 00 2f 00 90 02 14 2e 00 77 00 61 00 76 00 90 00 } //01 00 
		$a_03_11 = {2f 2f 38 32 2e 31 31 38 2e 32 31 2e 36 39 2f 79 69 79 2f 90 02 14 2e 77 61 76 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}