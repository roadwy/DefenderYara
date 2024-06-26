
rule Trojan_BAT_Injectgen_MB_MTB{
	meta:
		description = "Trojan:BAT/Injectgen.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 66 75 73 65 64 42 79 41 74 74 72 69 62 75 74 65 } //01 00  ConfusedByAttribute
		$a_81_1 = {73 76 63 68 6f 73 74 2e 65 78 65 } //01 00  svchost.exe
		$a_81_2 = {78 6d 72 2e 65 78 65 } //01 00  xmr.exe
		$a_01_3 = {49 73 4c 6f 67 67 69 6e 67 } //01 00  IsLogging
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_5 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //01 00  CreateEncryptor
		$a_01_6 = {5a 69 70 41 72 63 68 69 76 65 } //01 00  ZipArchive
		$a_01_7 = {73 65 74 5f 4b 65 79 53 69 7a 65 } //01 00  set_KeySize
		$a_01_8 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_01_9 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_10 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //01 00  SetThreadContext
		$a_01_11 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //01 00  VirtualAllocEx
		$a_01_12 = {5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //01 00  ZwUnmapViewOfSection
		$a_01_13 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  WriteProcessMemory
	condition:
		any of ($a_*)
 
}