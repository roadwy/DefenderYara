
rule TrojanDropper_BAT_VB_AA{
	meta:
		description = "TrojanDropper:BAT/VB.AA,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 08 00 00 02 00 "
		
	strings :
		$a_01_0 = {45 00 52 00 52 00 20 00 32 00 30 00 30 00 33 00 3a 00 20 00 } //03 00  ERR 2003: 
		$a_01_1 = {54 57 56 30 61 47 39 6b 53 55 51 3d } //03 00  TWV0aG9kSUQ=
		$a_01_2 = {54 6d 46 74 5a 51 3d 3d 3c 55 32 31 68 63 6e 52 42 63 33 4e 6c 62 57 4a 73 65 53 35 42 64 48 52 79 61 57 4a 31 64 47 56 7a 4c 6c 42 76 64 32 56 79 5a 57 52 43 65 55 46 30 64 48 4a 70 59 6e 56 30 5a 51 3d 3d } //03 00  TmFtZQ==<U21hcnRBc3NlbWJseS5BdHRyaWJ1dGVzLlBvd2VyZWRCeUF0dHJpYnV0ZQ==
		$a_01_3 = {58 32 6c 75 62 6d 56 79 52 58 68 6a 5a 58 42 30 61 57 39 75 24 56 57 35 6f 59 57 35 6b 62 47 56 6b 52 58 68 6a 5a 58 42 30 61 57 39 75 4c 6b 31 6c 64 47 68 76 5a 45 6c 45 24 56 57 35 6f 59 57 35 6b 62 47 56 6b 52 58 68 6a 5a 58 42 30 61 57 39 75 4c 6b 6c 4d 54 32 5a 6d 63 32 56 30 30 56 57 35 6f 59 57 35 6b 62 47 56 6b 52 58 68 6a 5a 58 42 30 61 57 39 75 4c 6c 42 79 5a 58 5a } //01 00  X2lubmVyRXhjZXB0aW9u$VW5oYW5kbGVkRXhjZXB0aW9uLk1ldGhvZElE$VW5oYW5kbGVkRXhjZXB0aW9uLklMT2Zmc2V00VW5oYW5kbGVkRXhjZXB0aW9uLlByZXZ
		$a_01_4 = {52 43 34 53 54 55 42 2e 4d 79 00 73 65 6e 64 65 72 00 } //ec ff  䍒匴啔⹂祍猀湥敤r
		$a_01_5 = {41 6d 61 7a 69 6e 67 20 49 6d 70 6f 72 74 65 72 2e 65 78 65 } //ec ff  Amazing Importer.exe
		$a_01_6 = {52 65 64 47 61 74 65 2e 53 51 4c 53 65 61 72 63 68 2e 41 64 64 69 6e 2e } //ec ff  RedGate.SQLSearch.Addin.
		$a_01_7 = {47 41 54 2e 41 43 45 2e 50 72 6f 70 65 72 74 69 65 73 } //00 00  GAT.ACE.Properties
	condition:
		any of ($a_*)
 
}