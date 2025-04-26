
rule Trojan_BAT_ElysiumStealer_DC_MTB{
	meta:
		description = "Trojan:BAT/ElysiumStealer.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,56 00 56 00 0b 00 00 "
		
	strings :
		$a_81_0 = {6a 6b 61 6c 73 6a 64 6e 61 73 6b 64 61 73 21 } //50 jkalsjdnaskdas!
		$a_81_1 = {79 67 64 73 66 73 64 32 } //50 ygdsfsd2
		$a_81_2 = {67 68 66 67 72 65 66 76 64 76 65 77 32 } //20 ghfgrefvdvew2
		$a_81_3 = {73 64 67 73 64 66 73 } //20 sdgsdfs
		$a_81_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //3 IsDebuggerPresent
		$a_81_5 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //3 ToBase64String
		$a_81_6 = {74 65 73 74 65 72 } //3 tester
		$a_81_7 = {44 65 63 6f 6d 70 72 65 73 73 } //3 Decompress
		$a_81_8 = {44 65 63 72 79 70 74 } //3 Decrypt
		$a_81_9 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_81_10 = {65 73 68 65 6c 6f 6e } //1 eshelon
	condition:
		((#a_81_0  & 1)*50+(#a_81_1  & 1)*50+(#a_81_2  & 1)*20+(#a_81_3  & 1)*20+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3+(#a_81_7  & 1)*3+(#a_81_8  & 1)*3+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=86
 
}