
rule Trojan_BAT_AgentTesla_TE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.TE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_1 = {24 63 66 61 32 38 63 37 37 2d 32 34 34 64 2d 34 31 38 61 2d 38 61 38 64 2d 66 37 64 39 31 63 35 33 38 37 36 39 } //01 00  $cfa28c77-244d-418a-8a8d-f7d91c538769
		$a_01_2 = {6c 69 6e 6b 44 6f 77 6e 6c 6f 61 64 } //01 00  linkDownload
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_4 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //01 00  CreateEncryptor
		$a_01_5 = {65 78 65 63 75 74 69 6f 6e 5f 70 61 72 61 6d } //01 00  execution_param
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_7 = {67 65 74 5f 48 6f 74 54 72 61 63 6b } //01 00  get_HotTrack
		$a_01_8 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_9 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00  DownloadFile
		$a_01_10 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00  InvokeMember
	condition:
		any of ($a_*)
 
}