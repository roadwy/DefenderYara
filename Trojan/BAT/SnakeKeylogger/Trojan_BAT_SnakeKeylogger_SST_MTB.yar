
rule Trojan_BAT_SnakeKeylogger_SST_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 "
		
	strings :
		$a_81_0 = {24 24 6d 65 74 68 6f 64 30 78 36 30 30 30 30 32 32 2d 31 } //1 $$method0x6000022-1
		$a_81_1 = {42 61 62 65 6c 4f 62 66 75 73 63 61 74 6f 72 41 74 74 72 69 62 75 74 65 } //1 BabelObfuscatorAttribute
		$a_81_2 = {66 73 61 66 61 66 77 77 77 77 77 77 77 77 61 66 } //1 fsafafwwwwwwwwaf
		$a_81_3 = {42 61 62 65 6c 41 74 74 72 69 62 75 74 65 } //1 BabelAttribute
		$a_81_4 = {53 75 70 70 72 65 73 73 49 6c 64 61 73 6d 41 74 74 72 69 62 75 74 65 } //1 SuppressIldasmAttribute
		$a_81_5 = {5f 73 74 61 63 6b 54 72 61 63 65 53 74 72 69 6e 67 } //1 _stackTraceString
		$a_81_6 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_81_7 = {43 61 6e 6f 6e 69 63 61 6c 69 7a 65 41 73 46 69 6c 65 50 61 74 68 } //1 CanonicalizeAsFilePath
		$a_81_8 = {43 72 79 70 74 6f 53 74 72 65 61 6d } //1 CryptoStream
		$a_81_9 = {50 41 5f 4e 6f 50 6c 61 74 66 6f 72 6d } //1 PA_NoPlatform
		$a_81_10 = {4e 69 6e 65 52 61 79 73 2e 4f 62 66 75 73 63 61 74 6f 72 2e 45 76 61 6c 75 61 74 69 6f 6e } //1 NineRays.Obfuscator.Evaluation
		$a_81_11 = {4d 6f 64 75 6c 65 42 75 69 6c 64 65 72 } //1 ModuleBuilder
		$a_81_12 = {42 69 74 43 6f 6e 76 65 72 74 65 72 } //1 BitConverter
		$a_81_13 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_14 = {31 39 38 20 50 72 6f 74 65 63 74 6f 72 20 56 32 } //1 198 Protector V2
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1) >=15
 
}
rule Trojan_BAT_SnakeKeylogger_SST_MTB_2{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,26 00 26 00 16 00 00 "
		
	strings :
		$a_81_0 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_81_1 = {67 65 74 5f 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 } //1 get_ExecutablePath
		$a_81_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_81_3 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_81_4 = {52 65 73 75 6d 65 4c 61 79 6f 75 74 } //1 ResumeLayout
		$a_81_5 = {53 74 72 69 6e 67 42 75 69 6c 64 65 72 } //1 StringBuilder
		$a_81_6 = {31 39 38 2d 50 72 6f 74 65 63 74 6f 72 } //1 198-Protector
		$a_81_7 = {41 73 79 6e 63 43 61 6c 6c 62 61 63 6b } //1 AsyncCallback
		$a_81_8 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_81_9 = {41 73 73 65 6d 62 6c 79 } //1 Assembly
		$a_81_10 = {53 75 70 70 72 65 73 73 49 6c 64 61 73 6d 41 74 74 72 69 62 75 74 65 } //1 SuppressIldasmAttribute
		$a_81_11 = {48 61 73 68 41 6c 67 6f 72 69 74 68 6d } //1 HashAlgorithm
		$a_81_12 = {49 43 72 79 70 74 6f 54 72 61 6e 73 66 6f 72 6d } //1 ICryptoTransform
		$a_81_13 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 TripleDESCryptoServiceProvider
		$a_81_14 = {73 65 74 5f 4b 65 79 } //1 set_Key
		$a_81_15 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_81_16 = {43 6f 70 79 54 6f } //1 CopyTo
		$a_81_17 = {43 6f 6d 70 75 74 65 48 61 73 68 } //1 ComputeHash
		$a_81_18 = {45 6e 63 6f 64 69 6e 67 } //1 Encoding
		$a_81_19 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //1 SymmetricAlgorithm
		$a_81_20 = {53 6e 61 6b 65 4c 6f 67 67 65 72 } //30 SnakeLogger
		$a_81_21 = {73 6e 61 6b 65 20 63 72 79 70 74 65 64 } //30 snake crypted
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1+(#a_81_16  & 1)*1+(#a_81_17  & 1)*1+(#a_81_18  & 1)*1+(#a_81_19  & 1)*1+(#a_81_20  & 1)*30+(#a_81_21  & 1)*30) >=38
 
}