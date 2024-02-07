
rule Backdoor_BAT_Crysan_ABL_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {57 17 02 1e 09 0a 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 45 00 00 00 14 00 00 00 0d 00 00 00 30 00 00 00 0b 00 00 00 } //01 00 
		$a_01_1 = {67 65 74 5f 49 73 41 74 74 61 63 68 65 64 } //01 00  get_IsAttached
		$a_01_2 = {49 73 4c 6f 67 67 69 6e 67 } //01 00  IsLogging
		$a_01_3 = {47 65 74 54 65 6d 70 50 61 74 68 } //01 00  GetTempPath
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_5 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_6 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 6b 00 20 00 53 00 54 00 41 00 52 00 54 00 } //00 00  cmd.exe /k START
	condition:
		any of ($a_*)
 
}