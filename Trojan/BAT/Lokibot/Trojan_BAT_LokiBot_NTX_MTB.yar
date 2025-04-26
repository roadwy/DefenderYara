
rule Trojan_BAT_LokiBot_NTX_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.NTX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {46 44 53 53 53 53 53 53 53 53 53 53 53 53 57 } //1 FDSSSSSSSSSSSSW
		$a_81_1 = {57 44 43 57 43 46 44 52 52 } //1 WDCWCFDRR
		$a_81_2 = {55 42 59 48 4e 59 47 56 54 42 46 56 54 52 } //1 UBYHNYGVTBFVTR
		$a_81_3 = {00 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 57 00 } //1
		$a_81_4 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_81_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}