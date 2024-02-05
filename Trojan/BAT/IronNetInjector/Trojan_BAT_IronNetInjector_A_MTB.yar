
rule Trojan_BAT_IronNetInjector_A_MTB{
	meta:
		description = "Trojan:BAT/IronNetInjector.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {49 6e 6a 65 63 74 69 6e 67 20 61 73 73 65 6d 62 6c 79 } //Injecting assembly  03 00 
		$a_80_1 = {53 74 61 72 74 69 6e 67 20 64 6f 74 6e 65 74 20 62 6f 6f 74 73 74 72 61 70 70 65 72 } //Starting dotnet bootstrapper  03 00 
		$a_80_2 = {41 73 73 65 6d 62 6c 79 20 69 6e 6a 65 63 74 65 64 } //Assembly injected  03 00 
		$a_80_3 = {49 6e 6a 65 63 74 69 6e 67 20 6e 61 74 69 76 65 20 6c 69 62 72 61 72 79 } //Injecting native library  03 00 
		$a_80_4 = {4e 65 74 49 6e 6a 65 63 74 6f 72 } //NetInjector  03 00 
		$a_80_5 = {47 65 74 46 75 6e 63 74 69 6f 6e 41 64 64 72 65 73 73 49 6e 54 61 72 67 65 74 33 32 50 72 6f 63 65 73 73 57 69 74 68 53 68 65 6c 6c } //GetFunctionAddressInTarget32ProcessWithShell  03 00 
		$a_80_6 = {50 65 4e 65 74 2e 53 74 72 75 63 74 75 72 65 73 } //PeNet.Structures  00 00 
	condition:
		any of ($a_*)
 
}