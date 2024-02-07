
rule Backdoor_BAT_Nanocore_ABD_MTB{
	meta:
		description = "Backdoor:BAT/Nanocore.ABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0a 00 00 03 00 "
		
	strings :
		$a_03_0 = {2b bf 00 02 28 e9 90 01 02 06 03 6f dd 90 01 02 06 02 28 eb 90 01 02 06 03 6f dd 90 01 02 06 02 28 ed 90 01 02 06 03 6f dd 90 01 02 06 02 fe 06 90 01 03 06 73 53 90 01 02 0a 02 fe 06 90 01 03 06 73 54 90 01 02 0a 28 42 90 01 02 06 0a 20 74 90 01 02 59 38 72 90 01 02 ff 2b 99 20 5c 90 01 02 6e 38 66 90 01 02 ff 2b f2 90 0a 6a 00 07 20 70 90 01 02 02 5a 20 92 90 01 02 98 61 90 00 } //01 00 
		$a_01_1 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_3 = {47 65 74 45 6e 75 6d 65 72 61 74 6f 72 } //01 00  GetEnumerator
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_5 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_6 = {52 65 73 6f 6c 76 65 4d 65 74 68 6f 64 } //01 00  ResolveMethod
		$a_01_7 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //01 00  CreateDelegate
		$a_01_8 = {52 65 61 64 42 79 74 65 73 } //01 00  ReadBytes
		$a_01_9 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}