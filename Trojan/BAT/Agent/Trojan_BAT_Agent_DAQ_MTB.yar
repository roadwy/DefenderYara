
rule Trojan_BAT_Agent_DAQ_MTB{
	meta:
		description = "Trojan:BAT/Agent.DAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 74 75 62 2e 65 78 65 } //01 00  Stub.exe
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_2 = {24 35 61 35 34 32 63 31 62 2d 32 64 33 36 2d 34 63 33 31 2d 62 30 33 39 2d 32 36 61 38 38 64 33 39 36 37 64 61 } //01 00  $5a542c1b-2d36-4c31-b039-26a88d3967da
		$a_81_3 = {44 65 62 75 67 67 65 72 20 44 65 74 65 63 74 65 64 } //01 00  Debugger Detected
		$a_01_4 = {53 74 75 62 2e 70 64 62 } //01 00  Stub.pdb
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_6 = {67 65 74 5f 4d 61 63 68 69 6e 65 4e 61 6d 65 } //01 00  get_MachineName
		$a_01_7 = {6e 6a 4c 6f 67 67 65 72 } //00 00  njLogger
	condition:
		any of ($a_*)
 
}