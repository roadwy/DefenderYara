
rule Trojan_BAT_CobaltStrike_STR_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.STR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_81_0 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_1 = {57 65 62 53 65 72 76 69 63 65 73 } //1 WebServices
		$a_81_2 = {43 6f 6e 74 61 69 6e 73 4b 65 79 } //1 ContainsKey
		$a_81_3 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //1 get_Assembly
		$a_81_4 = {67 65 74 5f 52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //1 get_ResourceManager
		$a_81_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_00_6 = {24 30 63 65 62 33 61 32 37 2d 31 63 66 39 2d 34 35 31 30 2d 38 36 64 31 2d 32 61 63 39 37 66 36 36 65 33 38 65 } //1 $0ceb3a27-1cf9-4510-86d1-2ac97f66e38e
		$a_81_7 = {4d 4a 77 55 67 63 6f 6b 51 76 } //1 MJwUgcokQv
		$a_81_8 = {48 69 64 65 4d 6f 64 75 6c 65 4e 61 6d 65 41 74 74 72 69 62 75 74 65 } //1 HideModuleNameAttribute
		$a_81_9 = {70 6f 6b 65 6d 6f 6e 5f 4c 6f 61 64 } //1 pokemon_Load
		$a_81_10 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_81_11 = {41 72 72 61 79 } //1 Array
		$a_81_12 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_81_13 = {43 6f 6e 76 65 72 74 } //1 Convert
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_00_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1) >=14
 
}