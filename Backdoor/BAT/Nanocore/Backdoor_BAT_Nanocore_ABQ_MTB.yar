
rule Backdoor_BAT_Nanocore_ABQ_MTB{
	meta:
		description = "Backdoor:BAT/Nanocore.ABQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 05 00 "
		
	strings :
		$a_03_0 = {00 03 02 03 6f 4f 90 01 02 0a 5d 6f 50 90 01 02 0a 7e 4c 90 01 02 04 02 91 61 d2 0a 2b 00 06 2a 90 00 } //01 00 
		$a_01_1 = {54 6f 53 74 72 69 6e 67 } //01 00  ToString
		$a_01_2 = {44 61 74 65 54 69 6d 65 4b 69 6e 64 } //01 00  DateTimeKind
		$a_01_3 = {44 65 6c 65 67 61 74 65 } //01 00  Delegate
		$a_01_4 = {45 6e 63 6f 64 69 6e 67 } //01 00  Encoding
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_6 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //00 00  get_Assembly
	condition:
		any of ($a_*)
 
}
rule Backdoor_BAT_Nanocore_ABQ_MTB_2{
	meta:
		description = "Backdoor:BAT/Nanocore.ABQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {2e 00 72 00 00 05 65 00 73 00 00 05 6f 00 75 00 00 05 72 00 63 00 00 } //01 00 
		$a_81_1 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 4e 61 6d 65 73 } //01 00  GetManifestResourceNames
		$a_81_2 = {6e 6a 63 76 6e 69 6f 64 73 6a 69 65 39 38 } //01 00  njcvniodsjie98
		$a_81_3 = {6b 6c 6e 76 61 77 } //01 00  klnvaw
		$a_81_4 = {32 32 53 32 79 32 32 32 32 73 32 32 32 74 32 32 65 32 32 32 6d 32 } //01 00  22S2y2222s222t22e222m2
		$a_81_5 = {32 32 52 32 65 32 66 32 32 32 6c 32 65 32 32 32 32 63 32 32 74 32 32 69 32 6f 32 6e 32 } //01 00  22R2e2f222l2e2222c22t22i2o2n2
		$a_81_6 = {41 32 32 32 73 32 73 32 65 32 6d 32 32 32 62 32 6c 32 79 32 } //01 00  A222s2s2e2m222b2l2y2
		$a_81_7 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00  InvokeMember
	condition:
		any of ($a_*)
 
}