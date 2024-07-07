
rule Trojan_BAT_Bladabindi_OET_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.OET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {65 63 36 33 32 66 64 39 2d 31 36 39 34 2d 34 66 34 61 2d 39 62 66 66 2d 66 32 30 36 30 30 65 33 37 39 38 31 } //1 ec632fd9-1694-4f4a-9bff-f20600e37981
		$a_81_1 = {67 65 74 5f 57 65 62 53 65 72 76 69 63 65 73 } //1 get_WebServices
		$a_81_2 = {48 61 73 68 74 61 62 6c 65 } //1 Hashtable
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_5 = {53 68 75 74 64 6f 77 6e 4d 6f 64 65 } //1 ShutdownMode
		$a_81_6 = {24 65 30 63 31 36 61 61 62 2d 66 36 36 62 2d 34 31 61 30 2d 62 36 31 61 2d 31 39 39 62 39 61 30 64 65 39 35 39 } //1 $e0c16aab-f66b-41a0-b61a-199b9a0de959
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}