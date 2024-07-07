
rule Backdoor_BAT_Crysan_ABH_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.ABH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 "
		
	strings :
		$a_01_0 = {57 ff b7 3f 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 69 04 00 00 a8 0c 00 00 b7 52 00 00 6c ca 00 00 b5 8e 00 00 3d 03 00 00 } //4
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {44 65 62 75 67 67 65 72 } //1 Debugger
		$a_01_4 = {67 65 74 5f 49 73 41 74 74 61 63 68 65 64 } //1 get_IsAttached
		$a_01_5 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_01_6 = {47 65 74 54 65 6d 70 50 61 74 68 } //1 GetTempPath
		$a_01_7 = {43 6f 6e 66 75 73 65 72 } //1 Confuser
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=11
 
}
rule Backdoor_BAT_Crysan_ABH_MTB_2{
	meta:
		description = "Backdoor:BAT/Crysan.ABH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {02 13 04 20 90 01 03 00 7e 90 01 03 04 7b 90 01 03 04 3a 90 01 03 ff 26 20 90 01 03 00 38 90 01 03 ff 11 07 6f 90 01 03 0a 11 04 16 11 04 8e 69 28 90 01 03 06 13 09 90 00 } //2
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_3 = {4b 00 73 00 69 00 72 00 75 00 6e 00 69 00 72 00 79 00 77 00 } //1 Ksiruniryw
		$a_01_4 = {56 00 7a 00 74 00 63 00 6e 00 76 00 66 00 6e 00 70 00 78 00 70 00 74 00 72 00 63 00 64 00 61 00 72 00 } //1 Vztcnvfnpxptrcdar
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}
rule Backdoor_BAT_Crysan_ABH_MTB_3{
	meta:
		description = "Backdoor:BAT/Crysan.ABH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {08 09 6f 19 90 01 02 0a 7e 13 90 01 02 04 73 1a 90 01 02 0a 13 06 11 06 02 7e 14 90 01 02 04 02 8e 69 6f 1b 90 01 02 0a 11 06 6f 1c 90 01 02 0a dd 0f 90 01 02 00 11 06 39 07 90 01 02 00 11 06 6f 1d 90 01 02 0a dc 08 6f 1e 90 01 02 0a 0a 90 00 } //5
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_4 = {62 74 71 62 71 77 77 63 65 74 61 63 72 63 65 61 74 72 77 62 2e 72 65 73 6f 75 72 63 65 73 } //1 btqbqwwcetacrceatrwb.resources
		$a_01_5 = {49 00 73 00 44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 50 00 72 00 65 00 73 00 65 00 6e 00 74 00 } //1 IsDebuggerPresent
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}