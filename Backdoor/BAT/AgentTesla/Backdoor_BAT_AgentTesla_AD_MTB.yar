
rule Backdoor_BAT_AgentTesla_AD_MTB{
	meta:
		description = "Backdoor:BAT/AgentTesla.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {72 22 01 00 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a [0-05] 6f ?? ?? ?? 0a 72 2e 01 00 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a [0-0a] 72 38 01 00 70 6f ?? ?? ?? 0a [0-05] 72 3c 01 00 70 6f ?? ?? ?? 0a [0-05] 72 40 01 00 70 6f ?? ?? ?? 0a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Backdoor_BAT_AgentTesla_AD_MTB_2{
	meta:
		description = "Backdoor:BAT/AgentTesla.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 11 00 00 "
		
	strings :
		$a_01_0 = {4f 62 66 75 73 63 61 74 65 64 42 79 47 6f 6c 69 61 74 68 } //1 ObfuscatedByGoliath
		$a_01_1 = {53 65 63 75 72 65 54 65 61 6d 2e 41 74 74 72 69 62 75 74 65 73 2e 4f 62 66 75 73 63 61 74 65 64 42 79 41 67 69 6c 65 44 6f 74 4e 65 74 41 74 74 72 69 62 75 74 65 } //1 SecureTeam.Attributes.ObfuscatedByAgileDotNetAttribute
		$a_01_2 = {59 61 6e 6f 41 74 74 72 69 62 75 74 65 } //1 YanoAttribute
		$a_01_3 = {5a 59 58 44 4e 47 75 61 72 64 65 72 } //1 ZYXDNGuarder
		$a_01_4 = {53 6d 61 72 74 41 73 73 65 6d 62 6c 79 2e 41 74 74 72 69 62 75 74 65 73 2e 50 6f 77 65 72 65 64 42 79 41 74 74 72 69 62 75 74 65 } //1 SmartAssembly.Attributes.PoweredByAttribute
		$a_01_5 = {49 4c 50 72 6f 74 65 63 74 6f 72 } //1 ILProtector
		$a_01_6 = {53 65 63 75 72 65 54 65 61 6d 2e 41 74 74 72 69 62 75 74 65 73 2e 4f 62 66 75 73 63 61 74 65 64 42 79 43 6c 69 53 65 63 75 72 65 41 74 74 72 69 62 75 74 65 } //1 SecureTeam.Attributes.ObfuscatedByCliSecureAttribute
		$a_01_7 = {58 65 6e 6f 63 6f 64 65 2e 43 6c 69 65 6e 74 2e 41 74 74 72 69 62 75 74 65 73 2e 41 73 73 65 6d 62 6c 79 41 74 74 72 69 62 75 74 65 73 2e 50 72 6f 63 65 73 73 65 64 42 79 58 65 6e 6f 63 6f 64 65 } //1 Xenocode.Client.Attributes.AssemblyAttributes.ProcessedByXenocode
		$a_01_8 = {49 4c 6f 76 65 54 68 65 52 65 61 6c 47 69 74 68 73 } //1 ILoveTheRealGiths
		$a_01_9 = {43 6f 6e 66 75 73 65 64 42 79 41 74 74 72 69 62 75 74 65 } //1 ConfusedByAttribute
		$a_01_10 = {42 61 62 65 6c 4f 62 66 75 73 63 61 74 6f 72 41 74 74 72 69 62 75 74 65 } //1 BabelObfuscatorAttribute
		$a_01_11 = {43 65 6e 74 6f 73 } //1 Centos
		$a_01_12 = {44 6f 74 66 75 73 63 61 74 6f 72 41 74 74 72 69 62 75 74 65 } //1 DotfuscatorAttribute
		$a_01_13 = {45 4d 79 50 49 44 5f 38 32 33 34 5f } //1 EMyPID_8234_
		$a_01_14 = {43 72 79 70 74 6f 4f 62 66 75 73 63 61 74 6f 72 2e 50 72 6f 74 65 63 74 65 64 57 69 74 68 43 72 79 70 74 6f 4f 62 66 75 73 63 61 74 6f 72 41 74 74 72 69 62 75 74 65 } //1 CryptoObfuscator.ProtectedWithCryptoObfuscatorAttribute
		$a_01_15 = {4e 69 6e 65 52 61 79 73 2e 4f 62 66 75 73 63 61 74 6f 72 2e 45 76 61 6c 75 61 74 69 6f 6e } //1 NineRays.Obfuscator.Evaluation
		$a_02_16 = {80 9a 01 00 80 94 5f 5f 5f 5f 90 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_02_16  & 1)*5) >=17
 
}