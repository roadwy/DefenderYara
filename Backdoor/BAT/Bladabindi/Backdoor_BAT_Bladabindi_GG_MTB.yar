
rule Backdoor_BAT_Bladabindi_GG_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 01 00 "
		
	strings :
		$a_81_0 = {6e 6a 53 74 75 62 } //01 00  njStub
		$a_81_1 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //01 00  CompressionMode
		$a_81_2 = {48 74 74 70 57 65 62 52 65 73 70 6f 6e 73 65 } //01 00  HttpWebResponse
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_4 = {67 65 74 5f 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 } //01 00  get_ExecutablePath
		$a_81_5 = {43 6f 70 79 46 72 6f 6d 53 63 72 65 65 6e } //01 00  CopyFromScreen
		$a_81_6 = {67 65 74 5f 50 6f 73 69 74 69 6f 6e } //01 00  get_Position
		$a_81_7 = {44 65 63 6f 6d 70 72 65 73 73 47 7a 69 70 } //01 00  DecompressGzip
		$a_81_8 = {48 69 64 64 65 6e 53 74 61 72 74 75 70 } //01 00  HiddenStartup
		$a_81_9 = {4e 74 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 } //01 00  NtSetInformationProcess
		$a_81_10 = {5c 44 6f 63 75 6d 65 6e 74 73 5c 64 6c 6c 68 6f 73 74 20 2f 66 } //01 00  \Documents\dllhost /f
		$a_81_11 = {63 6d 64 2e 65 78 65 20 2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 20 31 20 26 20 44 65 6c } //01 00  cmd.exe /C Y /N /D Y /T 1 & Del
		$a_81_12 = {44 6f 77 6e 6c 6f 61 64 20 45 52 52 4f 52 } //00 00  Download ERROR
	condition:
		any of ($a_*)
 
}