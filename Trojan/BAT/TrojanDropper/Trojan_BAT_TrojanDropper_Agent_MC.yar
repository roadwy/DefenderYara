
rule Trojan_BAT_TrojanDropper_Agent_MC{
	meta:
		description = "Trojan:BAT/TrojanDropper.Agent.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 01 00 "
		
	strings :
		$a_81_0 = {61 38 31 61 64 32 36 62 2d 63 66 66 35 2d 34 38 33 32 2d 61 31 64 32 2d 34 31 33 63 63 33 35 63 35 61 38 62 } //01 00  a81ad26b-cff5-4832-a1d2-413cc35c5a8b
		$a_81_1 = {48 61 73 68 53 74 65 61 6c 65 72 } //01 00  HashStealer
		$a_81_2 = {5a 69 70 46 69 6c 65 45 78 74 65 6e 73 69 6f 6e 73 } //01 00  ZipFileExtensions
		$a_81_3 = {41 6e 74 69 6d 61 6c 77 61 72 65 20 53 65 72 76 69 63 65 20 45 78 65 63 75 74 61 62 6c 65 } //01 00  Antimalware Service Executable
		$a_81_4 = {48 6f 73 74 20 50 72 6f 63 65 73 73 20 66 6f 72 20 57 69 6e 64 6f 77 73 20 53 65 72 76 69 63 65 73 } //01 00  Host Process for Windows Services
		$a_81_5 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_81_6 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_81_7 = {43 72 65 61 74 65 46 69 6c 65 } //01 00  CreateFile
		$a_81_8 = {67 65 74 5f 50 72 6f 63 65 73 73 4e 61 6d 65 } //01 00  get_ProcessName
		$a_81_9 = {57 72 69 74 65 4c 69 6e 65 } //01 00  WriteLine
		$a_81_10 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_11 = {47 65 74 53 74 72 69 6e 67 } //01 00  GetString
		$a_81_12 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_81_13 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_81_14 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //00 00  WriteAllBytes
	condition:
		any of ($a_*)
 
}