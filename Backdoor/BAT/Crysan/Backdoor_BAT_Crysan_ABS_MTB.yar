
rule Backdoor_BAT_Crysan_ABS_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 ff b7 3f 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 f5 03 00 00 47 0b 00 00 44 4e 00 00 } //01 00 
		$a_01_1 = {4f 6c 65 47 65 74 43 6c 69 70 62 6f 61 72 64 } //01 00  OleGetClipboard
		$a_01_2 = {67 65 74 5f 49 73 41 74 74 61 63 68 65 64 } //01 00  get_IsAttached
		$a_01_3 = {49 73 4c 6f 67 67 69 6e 67 } //01 00  IsLogging
		$a_01_4 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //01 00  CreateEncryptor
		$a_01_5 = {46 6c 75 73 68 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  FlushFinalBlock
		$a_01_6 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_7 = {43 6f 6e 66 75 73 65 72 45 78 } //00 00  ConfuserEx
	condition:
		any of ($a_*)
 
}