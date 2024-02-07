
rule Trojan_BAT_AgentTesla_SLS{
	meta:
		description = "Trojan:BAT/AgentTesla.SLS,SIGNATURE_TYPE_PEHSTR_EXT,20 03 20 03 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e } //01 00  System.Reflection
		$a_01_1 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 43 6f 6d 70 69 6c 65 72 53 65 72 76 69 63 65 73 } //01 00  System.Runtime.CompilerServices
		$a_01_2 = {43 6f 6d 70 69 6c 61 74 69 6f 6e 52 65 6c 61 78 61 74 69 6f 6e 73 41 74 74 72 69 62 75 74 65 } //01 00  CompilationRelaxationsAttribute
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_4 = {42 69 74 43 6f 6e 76 65 72 74 65 72 } //01 00  BitConverter
		$a_01_5 = {42 65 67 69 6e 49 6e 76 6f 6b 65 } //01 00  BeginInvoke
		$a_01_6 = {70 72 6f 63 65 73 73 49 6e 66 6f 72 6d 61 74 69 6f 6e } //01 00  processInformation
		$a_01_7 = {44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  DESCryptoServiceProvider
		$a_01_8 = {61 64 64 5f 41 73 73 65 6d 62 6c 79 52 65 73 6f 6c 76 65 } //01 00  add_AssemblyResolve
		$a_01_9 = {61 64 64 5f 52 65 73 6f 75 72 63 65 52 65 73 6f 6c 76 65 } //00 00  add_ResourceResolve
		$a_00_10 = {5d 04 00 00 90 32 } //05 80 
	condition:
		any of ($a_*)
 
}