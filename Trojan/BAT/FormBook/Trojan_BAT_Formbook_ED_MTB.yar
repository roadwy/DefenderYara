
rule Trojan_BAT_Formbook_ED_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_81_0 = {24 34 34 36 63 63 34 64 34 2d 32 61 39 33 2d 34 63 39 30 2d 62 66 34 35 2d 32 38 64 37 65 64 31 62 66 32 64 61 } //10 $446cc4d4-2a93-4c90-bf45-28d7ed1bf2da
		$a_81_1 = {50 72 6f 70 65 72 74 79 41 63 63 65 73 73 6f 72 2e 52 65 73 6f 75 72 63 65 73 } //1 PropertyAccessor.Resources
		$a_81_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_3 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_4 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_7 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=16
 
}
rule Trojan_BAT_Formbook_ED_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 08 00 00 "
		
	strings :
		$a_81_0 = {24 31 45 39 46 34 36 30 44 2d 32 38 45 46 2d 34 37 36 31 2d 41 36 39 44 2d 35 38 30 32 31 32 39 33 44 35 43 38 } //10 $1E9F460D-28EF-4761-A69D-58021293D5C8
		$a_81_1 = {24 61 38 61 31 39 32 34 39 2d 34 66 65 30 2d 34 37 38 62 2d 62 61 63 66 2d 32 62 32 62 35 35 61 34 39 61 63 33 } //10 $a8a19249-4fe0-478b-bacf-2b2b55a49ac3
		$a_81_2 = {46 6f 72 6d 61 74 74 65 72 53 69 6e 6b } //1 FormatterSink
		$a_81_3 = {50 61 69 6e 74 65 72 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 Painter.Form1.resources
		$a_81_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_7 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=15
 
}