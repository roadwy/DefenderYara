
rule Trojan_BAT_SpySnake_ML_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 19 07 02 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 08 18 58 0c 08 06 32 e3 } //5
		$a_01_1 = {57 15 02 08 09 0b 00 00 00 5a a4 00 00 16 00 00 01 00 00 00 31 } //5
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_3 = {65 61 61 62 37 32 62 63 2d 61 35 39 34 2d 34 39 62 64 2d 39 37 31 61 2d 36 39 36 62 64 63 65 39 33 62 39 66 } //1 eaab72bc-a594-49bd-971a-696bdce93b9f
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}
rule Trojan_BAT_SpySnake_ML_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {23 73 61 64 61 64 66 67 64 73 2e 64 6c 6c 23 } //1 #sadadfgds.dll#
		$a_01_1 = {63 00 68 00 72 00 6f 00 6d 00 5c 00 63 00 68 00 72 00 6f 00 6d 00 2e 00 65 00 78 00 65 00 } //1 chrom\chrom.exe
		$a_01_2 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
		$a_01_3 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_01_4 = {4f 62 66 75 73 63 61 74 65 64 42 79 47 6f 6c 69 61 74 68 } //1 ObfuscatedByGoliath
		$a_01_5 = {46 6c 75 73 68 46 69 6e 61 6c 42 6c 6f 63 6b } //1 FlushFinalBlock
		$a_01_6 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_7 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule Trojan_BAT_SpySnake_ML_MTB_3{
	meta:
		description = "Trojan:BAT/SpySnake.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 5d a2 c9 09 01 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 5d 00 00 00 0b 00 00 00 32 00 00 00 de 00 00 00 2e 00 00 00 92 } //5
		$a_01_1 = {35 36 31 65 37 61 39 33 2d 64 32 32 32 2d 34 63 62 64 2d 61 62 63 30 2d 35 39 63 37 30 65 38 62 37 34 65 64 } //2 561e7a93-d222-4cbd-abc0-59c70e8b74ed
		$a_01_2 = {5f 00 32 00 30 00 34 00 38 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 } //2 _2048WindowsFormsApp.Properties
		$a_01_3 = {52 00 75 00 6c 00 65 00 73 00 4f 00 66 00 54 00 68 00 65 00 47 00 61 00 6d 00 65 00 46 00 6f 00 72 00 6d 00 } //2 RulesOfTheGameForm
		$a_01_4 = {43 00 41 00 53 00 43 00 58 00 } //2 CASCX
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=13
 
}