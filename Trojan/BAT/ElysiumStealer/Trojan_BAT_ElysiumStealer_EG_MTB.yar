
rule Trojan_BAT_ElysiumStealer_EG_MTB{
	meta:
		description = "Trojan:BAT/ElysiumStealer.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,25 00 25 00 0c 00 00 "
		
	strings :
		$a_81_0 = {61 73 64 66 61 73 64 61 73 66 } //20 asdfasdasf
		$a_81_1 = {6a 68 67 66 6a 68 67 66 } //20 jhgfjhgf
		$a_81_2 = {79 75 74 79 75 75 79 79 74 75 } //20 yutyuuyytu
		$a_81_3 = {53 46 44 53 44 46 53 44 21 21 21 } //10 SFDSDFSD!!!
		$a_81_4 = {46 49 4c 45 54 59 50 45 5f 46 49 4c 45 5f 49 43 4f 4e 5f 31 38 37 37 } //1 FILETYPE_FILE_ICON_1877
		$a_81_5 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_6 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_81_7 = {74 65 73 74 65 72 } //1 tester
		$a_81_8 = {44 65 63 6f 6d 70 72 65 73 73 } //1 Decompress
		$a_81_9 = {44 65 63 72 79 70 74 } //1 Decrypt
		$a_81_10 = {52 65 76 65 72 73 65 44 65 63 6f 64 65 } //1 ReverseDecode
		$a_81_11 = {65 73 68 65 6c 6f 6e } //1 eshelon
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*20+(#a_81_3  & 1)*10+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=37
 
}