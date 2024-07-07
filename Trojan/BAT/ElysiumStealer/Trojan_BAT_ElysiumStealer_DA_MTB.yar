
rule Trojan_BAT_ElysiumStealer_DA_MTB{
	meta:
		description = "Trojan:BAT/ElysiumStealer.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2e 00 2e 00 0a 00 00 "
		
	strings :
		$a_81_0 = {6a 6b 61 6c 73 6a 64 6e 61 73 6b 64 61 73 21 } //20 jkalsjdnaskdas!
		$a_81_1 = {73 64 66 73 64 66 73 64 } //20 sdfsdfsd
		$a_81_2 = {67 64 73 66 61 73 64 73 61 23 } //20 gdsfasdsa#
		$a_81_3 = {61 73 66 61 64 66 61 73 64 61 73 64 73 61 } //20 asfadfasdasdsa
		$a_81_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_5 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_81_6 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_81_7 = {74 65 73 74 65 72 } //1 tester
		$a_81_8 = {44 65 63 6f 6d 70 72 65 73 73 } //1 Decompress
		$a_81_9 = {44 65 63 72 79 70 74 } //1 Decrypt
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*20+(#a_81_3  & 1)*20+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=46
 
}