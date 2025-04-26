
rule Trojan_BAT_Formbook_DF_MTB{
	meta:
		description = "Trojan:BAT/Formbook.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {24 46 39 37 35 32 35 42 45 2d 41 33 46 39 2d 34 38 36 32 2d 38 41 31 45 2d 44 36 30 39 38 42 45 37 42 45 37 43 } //1 $F97525BE-A3F9-4862-8A1E-D6098BE7BE7C
		$a_81_1 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_3 = {43 6f 6e 6e 65 63 74 69 6f 6e 53 74 72 69 6e 67 } //1 ConnectionString
		$a_81_4 = {53 65 6e 64 4f 72 50 6f 73 74 43 61 6c 6c 62 61 63 6b } //1 SendOrPostCallback
		$a_81_5 = {53 74 61 66 66 5f 50 61 73 73 63 6f 64 65 } //1 Staff_Passcode
		$a_81_6 = {4d 69 6c 6b 79 20 4c 61 6e 65 } //1 Milky Lane
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}