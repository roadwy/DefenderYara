
rule TrojanSpy_BAT_Stealergen_ML_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealergen.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 34 63 38 65 61 61 63 2d 34 36 63 31 2d 34 61 35 36 2d 39 39 36 31 2d 37 36 62 33 33 39 32 31 64 32 61 65 } //01 00  e4c8eaac-46c1-4a56-9961-76b33921d2ae
		$a_01_1 = {42 00 55 00 59 00 20 00 43 00 52 00 59 00 50 00 } //01 00  BUY CRYP
		$a_01_2 = {40 00 50 00 75 00 6c 00 73 00 61 00 72 00 43 00 72 00 79 00 70 00 74 00 65 00 72 00 5f 00 62 00 6f 00 74 00 } //01 00  @PulsarCrypter_bot
		$a_01_3 = {47 65 74 44 6f 6d 61 69 6e } //01 00  GetDomain
		$a_81_4 = {72 66 66 4f 74 4f 6c 68 52 42 7a 56 56 71 4b 50 41 44 59 70 } //01 00  rffOtOlhRBzVVqKPADYp
		$a_01_5 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_6 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_7 = {57 00 6f 00 77 00 36 00 34 00 47 00 65 00 74 00 54 00 68 00 72 00 65 00 61 00 64 00 43 00 6f 00 6e 00 74 00 65 00 78 00 74 00 } //01 00  Wow64GetThreadContext
		$a_01_8 = {47 00 65 00 74 00 54 00 68 00 72 00 65 00 61 00 64 00 43 00 6f 00 6e 00 74 00 65 00 78 00 74 00 } //01 00  GetThreadContext
		$a_01_9 = {52 00 65 00 61 00 64 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 } //01 00  ReadProcessMemory
		$a_01_10 = {57 00 72 00 69 00 74 00 65 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 } //01 00  WriteProcessMemory
		$a_01_11 = {53 00 65 00 74 00 54 00 68 00 72 00 65 00 61 00 64 00 43 00 6f 00 6e 00 74 00 65 00 78 00 74 00 } //01 00  SetThreadContext
		$a_01_12 = {44 00 79 00 6e 00 61 00 6d 00 69 00 63 00 44 00 6c 00 6c 00 49 00 6e 00 76 00 6f 00 6b 00 65 00 } //01 00  DynamicDllInvoke
		$a_01_13 = {44 00 79 00 6e 00 61 00 6d 00 69 00 63 00 44 00 6c 00 6c 00 4d 00 6f 00 64 00 75 00 6c 00 65 00 } //01 00  DynamicDllModule
		$a_01_14 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //00 00  Invoke
	condition:
		any of ($a_*)
 
}