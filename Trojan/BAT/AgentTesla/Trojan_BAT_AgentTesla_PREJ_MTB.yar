
rule Trojan_BAT_AgentTesla_PREJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PREJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0e 00 00 01 00 "
		
	strings :
		$a_81_0 = {46 69 6a 6b 6f 72 65 67 } //01 00  Fijkoreg
		$a_81_1 = {4b 66 6f 70 65 77 66 } //01 00  Kfopewf
		$a_81_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_81_4 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //01 00  GetExportedTypes
		$a_81_5 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_81_6 = {73 74 61 74 65 4d 61 63 68 69 6e 65 } //01 00  stateMachine
		$a_81_7 = {45 66 65 6b 6f 77 71 79 67 6e 62 } //01 00  Efekowqygnb
		$a_81_8 = {44 65 6a 65 67 } //01 00  Dejeg
		$a_81_9 = {41 73 79 6e 63 54 61 73 6b 4d 65 74 68 6f 64 42 75 69 6c 64 65 72 } //01 00  AsyncTaskMethodBuilder
		$a_81_10 = {41 70 70 44 6f 6d 61 69 6e } //01 00  AppDomain
		$a_81_11 = {24 65 36 32 63 37 39 31 38 2d 34 65 34 33 2d 34 64 30 61 2d 61 30 30 31 2d 33 66 33 30 39 35 64 39 38 33 36 32 } //01 00  $e62c7918-4e43-4d0a-a001-3f3095d98362
		$a_03_12 = {31 00 30 00 33 00 2e 00 32 00 32 00 38 00 2e 00 33 00 36 00 2e 00 31 00 30 00 34 00 2f 00 75 00 6c 00 74 00 72 00 6f 00 6e 00 2f 00 90 02 14 2e 00 77 00 61 00 76 00 90 00 } //01 00 
		$a_03_13 = {31 30 33 2e 32 32 38 2e 33 36 2e 31 30 34 2f 75 6c 74 72 6f 6e 2f 90 02 14 2e 77 61 76 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}