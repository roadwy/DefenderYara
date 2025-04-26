
rule Trojan_BAT_Tnega_MS_MTB{
	meta:
		description = "Trojan:BAT/Tnega.MS!MTB,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 11 00 00 "
		
	strings :
		$a_01_0 = {41 70 70 6c 79 52 65 71 75 65 73 74 2e 64 6c 6c } //1 ApplyRequest.dll
		$a_01_1 = {53 63 72 69 70 74 44 44 4c } //1 ScriptDDL
		$a_01_2 = {5f 6c 73 74 53 74 61 74 75 73 45 78 65 63 } //1 _lstStatusExec
		$a_01_3 = {5f 75 73 65 72 50 61 73 73 77 6f 72 64 } //1 _userPassword
		$a_01_4 = {5f 64 73 52 65 71 75 65 73 74 } //1 _dsRequest
		$a_01_5 = {5f 72 65 71 53 63 72 69 70 74 } //1 _reqScript
		$a_01_6 = {5f 66 72 61 6d 65 53 65 72 76 65 72 } //1 _frameServer
		$a_01_7 = {5f 72 65 71 75 65 73 74 53 65 72 76 65 72 } //1 _requestServer
		$a_01_8 = {45 78 65 63 75 74 65 41 6c 6c 53 74 65 70 73 } //1 ExecuteAllSteps
		$a_01_9 = {61 64 64 5f 53 65 6e 64 53 74 61 74 75 73 52 65 71 75 65 73 74 } //1 add_SendStatusRequest
		$a_01_10 = {53 65 6e 64 50 72 6f 67 72 65 73 73 45 78 65 63 } //1 SendProgressExec
		$a_01_11 = {47 65 72 61 72 53 63 72 69 70 74 73 44 72 6f 70 } //1 GerarScriptsDrop
		$a_01_12 = {47 65 74 4c 69 73 74 52 65 70 6c 61 63 65 44 6c 6c } //1 GetListReplaceDll
		$a_01_13 = {56 65 72 69 66 69 63 61 46 6f 72 65 69 67 6e 4b 65 79 73 } //1 VerificaForeignKeys
		$a_01_14 = {6c 62 6c 63 6f 6d 70 75 74 61 64 6f 72 72 65 73 70 6f 6e 73 61 76 65 6c } //1 lblcomputadorresponsavel
		$a_01_15 = {74 78 74 55 73 65 72 5f 56 61 6c 69 64 61 74 65 64 } //1 txtUser_Validated
		$a_01_16 = {56 65 72 69 66 69 63 61 56 65 72 73 61 6f 50 6c 75 67 69 6e } //1 VerificaVersaoPlugin
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1) >=12
 
}