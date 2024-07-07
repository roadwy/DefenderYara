
rule Trojan_BAT_ElysiumStealer_DE_MTB{
	meta:
		description = "Trojan:BAT/ElysiumStealer.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 0a 00 00 "
		
	strings :
		$a_81_0 = {61 6b 73 61 64 6b 73 6b 61 } //20 aksadkska
		$a_81_1 = {73 64 66 73 61 64 73 64 73 } //20 sdfsadsds
		$a_81_2 = {68 64 66 67 68 64 66 68 64 66 67 64 66 67 } //20 hdfghdfhdfgdfg
		$a_81_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_4 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_81_5 = {74 65 73 74 65 72 } //1 tester
		$a_81_6 = {44 65 63 6f 6d 70 72 65 73 73 } //1 Decompress
		$a_81_7 = {44 65 63 72 79 70 74 } //1 Decrypt
		$a_81_8 = {52 65 76 65 72 73 65 44 65 63 6f 64 65 } //1 ReverseDecode
		$a_81_9 = {65 73 68 65 6c 6f 6e } //1 eshelon
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*20+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=27
 
}