
rule Trojan_BAT_Formbook_ER_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 09 00 00 "
		
	strings :
		$a_81_0 = {24 35 66 31 64 39 30 39 32 2d 38 63 62 62 2d 34 65 37 33 2d 62 32 36 63 2d 38 30 61 33 63 31 64 37 65 31 66 37 } //20 $5f1d9092-8cbb-4e73-b26c-80a3c1d7e1f7
		$a_81_1 = {24 64 65 63 39 65 66 65 66 2d 64 66 61 64 2d 34 39 65 30 2d 61 61 65 66 2d 33 33 32 32 63 39 38 33 61 32 35 36 } //20 $dec9efef-dfad-49e0-aaef-3322c983a256
		$a_81_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_3 = {46 6f 72 6d 73 50 72 69 6e 74 53 63 61 6c 69 6e 67 42 6c 75 72 72 79 49 73 73 75 65 2e 53 69 6e 6b 53 74 61 63 6b 2e 72 65 73 6f 75 72 63 65 73 } //1 FormsPrintScalingBlurryIssue.SinkStack.resources
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_5 = {41 70 70 6c 69 63 61 74 69 6f 6e 54 72 75 73 74 4d 61 6e 61 67 65 72 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 ApplicationTrustManager.My.Resources
		$a_81_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_8 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=25
 
}