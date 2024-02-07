
rule Trojan_BAT_Crysan_LWT_MTB{
	meta:
		description = "Trojan:BAT/Crysan.LWT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 0c 00 00 01 00 "
		
	strings :
		$a_81_0 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_81_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_2 = {47 65 74 53 74 72 69 6e 67 } //01 00  GetString
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_81_4 = {57 65 62 43 6c 69 65 6e 74 } //14 00  WebClient
		$a_80_5 = {6c 61 75 72 65 6e 74 70 72 6f 74 65 63 74 6f 72 2e 63 6f 6d } //laurentprotector.com  0a 00 
		$a_80_6 = {4e 6e 51 46 71 73 4f 45 55 74 6b 65 7a 76 49 45 63 4c 70 66 61 2e 67 63 75 51 67 4d 41 42 49 4e 63 79 67 67 44 4d 42 78 50 71 76 } //NnQFqsOEUtkezvIEcLpfa.gcuQgMABINcyggDMBxPqv  0a 00 
		$a_80_7 = {4f 53 4f 5a 76 44 73 66 78 7a 51 4e 6d 6b 65 51 64 43 6f 73 76 } //OSOZvDsfxzQNmkeQdCosv  0a 00 
		$a_80_8 = {47 65 2e 6e 74 66 51 55 52 56 78 4b 45 76 43 6f 46 79 50 4e 6f 4f 5a 45 54 75 74 49 51 43 } //Ge.ntfQURVxKEvCoFyPNoOZETutIQC  0a 00 
		$a_80_9 = {65 6b 59 64 4f 44 4d 67 4a 43 61 54 50 42 43 74 50 44 4e 72 44 61 57 4c 4a 57 6f } //ekYdODMgJCaTPBCtPDNrDaWLJWo  0a 00 
		$a_81_10 = {56 6f 69 7a 73 } //0a 00  Voizs
		$a_81_11 = {43 61 62 72 69 6f 6c 65 74 } //00 00  Cabriolet
	condition:
		any of ($a_*)
 
}