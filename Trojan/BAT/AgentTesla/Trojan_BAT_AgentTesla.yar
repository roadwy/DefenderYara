
rule Trojan_BAT_AgentTesla{
	meta:
		description = "Trojan:BAT/AgentTesla,SIGNATURE_TYPE_PEHSTR_EXT,6e 00 6e 00 19 00 00 0a 00 "
		
	strings :
		$a_01_0 = {50 72 6f 63 65 73 73 65 64 42 79 58 65 6e 6f 63 6f 64 65 } //0a 00  ProcessedByXenocode
		$a_01_1 = {53 6d 61 72 74 41 73 73 65 6d 62 6c 79 2e 41 74 74 72 69 62 75 74 65 73 2e 50 6f 77 65 72 65 64 42 79 41 74 74 72 69 62 75 74 65 } //0a 00  SmartAssembly.Attributes.PoweredByAttribute
		$a_01_2 = {4e 69 6e 65 52 61 79 73 2e 4f 62 66 75 73 63 61 74 6f 72 2e 45 76 61 6c 75 61 74 69 6f 6e } //0a 00  NineRays.Obfuscator.Evaluation
		$a_01_3 = {4f 62 66 75 73 63 61 74 65 64 42 79 47 6f 6c 69 61 74 68 } //0a 00  ObfuscatedByGoliath
		$a_01_4 = {59 61 6e 6f 41 74 74 72 69 62 75 74 65 } //0a 00  YanoAttribute
		$a_01_5 = {42 61 62 65 6c 4f 62 66 75 73 63 61 74 6f 72 41 74 74 72 69 62 75 74 65 } //0a 00  BabelObfuscatorAttribute
		$a_81_6 = {43 72 79 70 74 6f 4f 62 66 75 73 63 61 74 6f 72 2e 50 72 6f 74 65 63 74 65 64 57 69 74 68 43 72 79 70 74 6f 4f 62 66 75 73 63 61 74 6f 72 41 74 74 72 69 62 75 74 65 } //0a 00  CryptoObfuscator.ProtectedWithCryptoObfuscatorAttribute
		$a_81_7 = {44 6f 74 4e 65 74 50 61 74 63 68 65 72 4f 62 66 75 73 63 61 74 6f 72 41 74 74 72 69 62 75 74 65 } //0a 00  DotNetPatcherObfuscatorAttribute
		$a_81_8 = {44 6f 74 66 75 73 63 61 74 6f 72 41 74 74 72 69 62 75 74 65 } //0a 00  DotfuscatorAttribute
		$a_01_9 = {44 6f 74 4e 65 74 50 61 74 63 68 65 72 50 61 63 6b 65 72 41 74 74 72 69 62 75 74 65 } //01 00  DotNetPatcherPackerAttribute
		$a_01_10 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 53 00 79 00 73 00 74 00 65 00 6d 00 } //01 00  Select * from Win32_ComputerSystem
		$a_01_11 = {53 75 70 70 72 65 73 73 55 6e 6d 61 6e 61 67 65 64 43 6f 64 65 53 65 63 75 72 69 74 79 } //01 00  SuppressUnmanagedCodeSecurity
		$a_01_12 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 00 44 65 66 69 6e 65 44 79 6e 61 6d 69 63 41 73 73 65 6d 62 6c 79 } //01 00 
		$a_01_13 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  CheckRemoteDebuggerPresent
		$a_01_14 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_01_15 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 43 6f 6d 70 69 6c 65 72 53 65 72 76 69 63 65 73 } //01 00  System.Runtime.CompilerServices
		$a_01_16 = {44 65 62 75 67 67 65 72 00 4d 61 6e 61 67 65 6d 65 6e 74 4f 62 6a 65 63 74 53 65 61 72 63 68 65 72 } //01 00 
		$a_01_17 = {44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  DESCryptoServiceProvider
		$a_01_18 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //01 00  GetExecutingAssembly
		$a_01_19 = {4d 65 74 68 6f 64 49 6d 70 6c 41 74 74 72 69 62 75 74 65 73 } //01 00  MethodImplAttributes
		$a_01_20 = {6c 70 50 72 6f 63 65 73 73 41 74 74 72 69 62 75 74 65 73 } //01 00  lpProcessAttributes
		$a_01_21 = {43 6f 6d 70 69 6c 61 74 69 6f 6e 52 65 6c 61 78 61 74 69 6f 6e 73 41 74 74 72 69 62 75 74 65 } //01 00  CompilationRelaxationsAttribute
		$a_01_22 = {43 6f 6d 70 69 6c 65 72 47 65 6e 65 72 61 74 65 64 41 74 74 72 69 62 75 74 65 } //01 00  CompilerGeneratedAttribute
		$a_01_23 = {55 6e 76 65 72 69 66 69 61 62 6c 65 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  UnverifiableCodeAttribute
		$a_01_24 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerBrowsableAttribute
		$a_00_25 = {7e 15 00 00 01 89 39 5e 1f 05 99 4a a4 5a 62 f4 03 e0 39 f3 00 00 00 00 cd 7e 15 00 00 07 b5 3d d3 83 30 29 4b b0 7d fc ea 49 cb b6 6d 00 00 00 00 cd 7e 15 00 00 30 8a f1 e9 c0 57 f0 43 91 b6 07 96 b6 81 01 90 00 00 00 00 cd 7e 15 00 00 3a 8b dc 35 a6 b8 5e 40 88 63 3f c0 26 d2 d8 6a 00 00 00 00 cd } //7e 15 
	condition:
		any of ($a_*)
 
}