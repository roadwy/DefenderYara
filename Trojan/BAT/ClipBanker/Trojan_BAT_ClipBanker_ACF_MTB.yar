
rule Trojan_BAT_ClipBanker_ACF_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.ACF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 18 00 0b 00 00 "
		
	strings :
		$a_80_0 = {79 6f 75 72 42 54 43 41 64 64 72 65 73 73 } //yourBTCAddress  5
		$a_80_1 = {53 74 61 72 74 47 72 61 62 62 69 6e 67 } //StartGrabbing  5
		$a_80_2 = {4d 69 6e 65 72 } //Miner  5
		$a_80_3 = {50 72 6f 6d 70 74 4f 6e 53 65 63 75 72 65 44 65 73 6b 74 6f 70 } //PromptOnSecureDesktop  5
		$a_80_4 = {43 6f 6e 73 65 6e 74 50 72 6f 6d 70 74 42 65 68 61 76 69 6f 72 41 64 6d 69 6e } //ConsentPromptBehaviorAdmin  5
		$a_80_5 = {28 57 69 6e 64 6f 77 73 52 75 6e 74 69 6d 65 42 72 6f 6b 65 72 29 } //(WindowsRuntimeBroker)  4
		$a_80_6 = {70 61 79 6c 6f 61 64 42 75 66 66 65 72 } //payloadBuffer  4
		$a_80_7 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 } //Add-MpPreference -ExclusionPath  4
		$a_80_8 = {53 65 74 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 50 55 41 50 72 6f 74 65 63 74 69 6f 6e } //Set-MpPreference -PUAProtection  4
		$a_80_9 = {44 69 73 61 62 6c 65 4e 6f 74 69 66 69 63 61 74 69 6f 6e 73 } //DisableNotifications  4
		$a_80_10 = {44 65 74 65 63 74 56 69 72 74 75 61 6c 4d 61 63 68 69 6e 65 } //DetectVirtualMachine  4
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5+(#a_80_3  & 1)*5+(#a_80_4  & 1)*5+(#a_80_5  & 1)*4+(#a_80_6  & 1)*4+(#a_80_7  & 1)*4+(#a_80_8  & 1)*4+(#a_80_9  & 1)*4+(#a_80_10  & 1)*4) >=24
 
}