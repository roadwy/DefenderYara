
rule Trojan_BAT_SpySnake_MO_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {57 9f b6 2b 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 83 00 00 00 36 00 00 00 69 00 00 00 4c 01 00 00 1b 01 00 00 0e } //05 00 
		$a_01_1 = {56 69 72 74 75 61 6c 4d 65 6d 53 69 6d 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00  VirtualMemSim.Properties
		$a_01_2 = {4c 61 7a 79 4c 69 73 74 } //01 00  LazyList
		$a_01_3 = {67 65 74 5f 50 72 6f 63 65 73 73 49 44 } //01 00  get_ProcessID
		$a_01_4 = {63 6f 6e 6e 65 63 74 69 6f 6e 49 64 } //00 00  connectionId
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_SpySnake_MO_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 4b 69 6e 73 6f 6b 75 } //01 00  SoftKinsoku
		$a_01_1 = {62 38 62 33 35 34 32 37 2d 37 62 32 62 2d 34 31 65 39 2d 38 61 35 62 2d 35 35 30 37 65 33 38 37 30 63 31 32 } //01 00  b8b35427-7b2b-41e9-8a5b-5507e3870c12
		$a_01_2 = {43 61 6c 7a 6f 6e 65 } //01 00  Calzone
		$a_01_3 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_5 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_6 = {44 65 6c 65 74 65 45 78 74 72 61 63 74 69 6f 6e 46 6f 6c 64 65 72 } //01 00  DeleteExtractionFolder
		$a_01_7 = {48 69 64 64 65 6e 72 65 73 65 72 76 65 64 } //01 00  Hiddenreserved
		$a_01_8 = {4d 69 73 73 69 6e 67 4c 6f 63 6b 53 74 61 74 65 } //01 00  MissingLockState
		$a_01_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_10 = {55 70 70 65 72 63 61 73 65 } //01 00  Uppercase
		$a_01_11 = {44 65 62 75 67 } //01 00  Debug
		$a_01_12 = {67 65 74 5f 48 69 64 64 65 6e } //01 00  get_Hidden
		$a_01_13 = {55 70 70 65 72 4c 65 66 74 } //00 00  UpperLeft
	condition:
		any of ($a_*)
 
}