
rule Trojan_BAT_AgentTesla_PAC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {45 72 61 73 65 45 78 70 72 65 73 73 69 6f 6e 46 72 6f 6d 48 69 73 74 6f 72 79 53 63 72 65 65 6e } //1 EraseExpressionFromHistoryScreen
		$a_01_1 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_01_2 = {67 65 74 5f 4f 66 66 73 65 74 4d 61 72 73 68 61 6c 65 72 } //1 get_OffsetMarshaler
		$a_01_3 = {53 65 6c 65 63 74 69 6e 67 4f 70 65 72 61 74 69 6f 6e } //1 SelectingOperation
		$a_01_4 = {50 65 72 66 6f 72 6d 4f 70 65 72 61 74 69 6f 6e } //1 PerformOperation
		$a_01_5 = {43 61 6c 63 75 6c 61 74 6f 72 53 74 61 74 65 } //1 CalculatorState
		$a_01_6 = {67 65 74 5f 54 75 72 71 75 6f 69 73 65 } //1 get_Turquoise
		$a_01_7 = {67 65 74 5f 50 72 65 63 69 73 69 6f 6e } //1 get_Precision
		$a_01_8 = {73 65 74 5f 50 72 65 63 69 73 69 6f 6e } //1 set_Precision
		$a_01_9 = {58 6d 6c 54 65 78 74 57 72 69 74 65 72 } //1 XmlTextWriter
		$a_01_10 = {4a 75 73 74 45 78 65 63 75 74 65 64 } //1 JustExecuted
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}