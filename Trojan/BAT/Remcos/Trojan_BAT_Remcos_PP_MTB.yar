
rule Trojan_BAT_Remcos_PP_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 09 00 00 "
		
	strings :
		$a_01_0 = {24 41 45 35 45 33 41 46 43 2d 39 43 32 45 2d 34 43 33 38 2d 41 43 30 31 2d 38 35 43 31 39 39 44 31 39 46 33 41 } //20 $AE5E3AFC-9C2E-4C38-AC01-85C199D19F3A
		$a_81_1 = {24 38 30 65 32 30 66 61 33 2d 38 37 65 65 2d 34 64 64 36 2d 62 66 30 39 2d 64 39 36 62 61 34 35 32 37 31 34 34 } //20 $80e20fa3-87ee-4dd6-bf09-d96ba4527144
		$a_81_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_3 = {47 61 6d 65 50 72 6f 6a 65 63 74 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 GameProject.My.Resources
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_5 = {50 4d 5f 46 6f 72 6d 73 41 76 67 43 61 6c 63 2e 52 65 73 6f 75 72 63 65 73 } //1 PM_FormsAvgCalc.Resources
		$a_81_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_8 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_01_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=25
 
}