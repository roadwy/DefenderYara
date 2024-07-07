
rule Trojan_BAT_ElysiumStealer_DY_MTB{
	meta:
		description = "Trojan:BAT/ElysiumStealer.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 0a 00 00 "
		
	strings :
		$a_81_0 = {65 72 79 74 72 65 77 72 } //20 erytrewr
		$a_81_1 = {64 66 67 73 64 66 73 64 66 73 } //20 dfgsdfsdfs
		$a_81_2 = {46 49 4c 45 54 59 50 45 5f 46 49 4c 45 5f 49 43 4f 4e 5f 31 38 37 37 } //1 FILETYPE_FILE_ICON_1877
		$a_81_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_4 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_81_5 = {74 65 73 74 65 72 } //1 tester
		$a_81_6 = {44 65 63 6f 6d 70 72 65 73 73 } //1 Decompress
		$a_81_7 = {44 65 63 72 79 70 74 } //1 Decrypt
		$a_81_8 = {52 65 76 65 72 73 65 44 65 63 6f 64 65 } //1 ReverseDecode
		$a_81_9 = {65 73 68 65 6c 6f 6e } //1 eshelon
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=27
 
}