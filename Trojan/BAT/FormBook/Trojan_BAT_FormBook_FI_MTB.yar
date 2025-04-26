
rule Trojan_BAT_FormBook_FI_MTB{
	meta:
		description = "Trojan:BAT/FormBook.FI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 0e 00 00 "
		
	strings :
		$a_81_0 = {75 79 33 32 65 31 32 33 } //20 uy32e123
		$a_81_1 = {73 64 66 73 64 66 73 61 64 65 61 } //20 sdfsdfsadea
		$a_81_2 = {67 73 64 66 61 73 64 66 61 73 } //20 gsdfasdfas
		$a_81_3 = {64 69 6b 33 69 61 6f 77 64 61 73 64 } //20 dik3iaowdasd
		$a_81_4 = {6d 6b 61 73 6b 64 61 64 61 73 } //20 mkaskdadas
		$a_81_5 = {4e 6f 6e 20 4f 62 66 75 73 63 61 74 65 64 } //1 Non Obfuscated
		$a_81_6 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_81_7 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_81_8 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_81_9 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_10 = {52 65 73 6f 6c 76 65 53 69 67 6e 61 74 75 72 65 } //1 ResolveSignature
		$a_81_11 = {4c 6f 61 64 4d 6f 64 75 6c 65 } //1 LoadModule
		$a_81_12 = {43 6f 6e 76 65 72 74 } //1 Convert
		$a_81_13 = {47 65 74 54 79 70 65 73 } //1 GetTypes
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*20+(#a_81_3  & 1)*20+(#a_81_4  & 1)*20+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1) >=28
 
}