
rule Trojan_BAT_Injuke_MA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 08 16 08 8e 69 6f 90 01 03 0a 07 6f 90 01 03 0a 16 6a 31 0d 08 2c 0a 07 6f 90 01 03 0a 13 05 de 0a de 06 90 00 } //02 00 
		$a_03_1 = {72 01 00 00 70 28 04 00 00 06 90 01 01 2d 03 26 2b 07 80 01 00 00 04 2b 00 2a 90 00 } //02 00 
		$a_01_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //01 00  powershell
		$a_01_3 = {57 65 62 52 65 71 75 65 73 74 } //01 00  WebRequest
		$a_01_4 = {54 68 72 65 61 64 53 74 61 72 74 } //01 00  ThreadStart
		$a_01_5 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00  InvokeMember
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Injuke_MA_MTB_2{
	meta:
		description = "Trojan:BAT/Injuke.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 11 01 28 1f 00 00 06 13 02 38 d8 00 00 00 11 08 17 6f 90 01 03 0a 38 a0 00 00 00 11 02 11 03 20 e8 03 00 00 73 90 01 01 00 00 0a 13 04 38 18 00 00 00 1e 8d 17 00 00 01 25 d0 16 00 00 04 28 90 01 03 0a 13 03 38 d3 ff ff ff 11 08 11 04 11 08 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 38 93 00 00 00 11 05 11 08 6f 90 01 03 0a 17 73 90 01 01 00 00 0a 13 06 38 00 00 00 00 00 11 06 03 16 03 8e 69 6f 90 01 03 0a 38 00 00 00 00 11 06 6f 90 01 03 0a 38 00 00 00 00 dd 3b 90 00 } //01 00 
		$a_81_1 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_81_2 = {67 65 74 5f 4b 65 79 53 69 7a 65 } //01 00  get_KeySize
		$a_81_3 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_81_4 = {73 65 74 5f 4b 65 79 } //01 00  set_Key
		$a_81_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_81_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_7 = {70 6f 77 65 72 73 68 65 6c 6c } //01 00  powershell
		$a_81_8 = {54 65 73 74 2d 43 6f 6e 6e 65 63 74 69 6f 6e } //01 00  Test-Connection
		$a_81_9 = {53 6c 65 65 70 } //01 00  Sleep
		$a_81_10 = {4e 65 77 4d 6f 63 6b } //01 00  NewMock
		$a_81_11 = {43 6f 6c 6c 65 63 74 4d 6f 63 6b } //01 00  CollectMock
		$a_81_12 = {73 65 74 5f 43 72 65 61 74 65 4e 6f 57 69 6e 64 6f 77 } //00 00  set_CreateNoWindow
	condition:
		any of ($a_*)
 
}