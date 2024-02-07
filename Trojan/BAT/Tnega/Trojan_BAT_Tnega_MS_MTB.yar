
rule Trojan_BAT_Tnega_MS_MTB{
	meta:
		description = "Trojan:BAT/Tnega.MS!MTB,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 11 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 70 70 6c 79 52 65 71 75 65 73 74 2e 64 6c 6c } //01 00  ApplyRequest.dll
		$a_01_1 = {53 63 72 69 70 74 44 44 4c } //01 00  ScriptDDL
		$a_01_2 = {5f 6c 73 74 53 74 61 74 75 73 45 78 65 63 } //01 00  _lstStatusExec
		$a_01_3 = {5f 75 73 65 72 50 61 73 73 77 6f 72 64 } //01 00  _userPassword
		$a_01_4 = {5f 64 73 52 65 71 75 65 73 74 } //01 00  _dsRequest
		$a_01_5 = {5f 72 65 71 53 63 72 69 70 74 } //01 00  _reqScript
		$a_01_6 = {5f 66 72 61 6d 65 53 65 72 76 65 72 } //01 00  _frameServer
		$a_01_7 = {5f 72 65 71 75 65 73 74 53 65 72 76 65 72 } //01 00  _requestServer
		$a_01_8 = {45 78 65 63 75 74 65 41 6c 6c 53 74 65 70 73 } //01 00  ExecuteAllSteps
		$a_01_9 = {61 64 64 5f 53 65 6e 64 53 74 61 74 75 73 52 65 71 75 65 73 74 } //01 00  add_SendStatusRequest
		$a_01_10 = {53 65 6e 64 50 72 6f 67 72 65 73 73 45 78 65 63 } //01 00  SendProgressExec
		$a_01_11 = {47 65 72 61 72 53 63 72 69 70 74 73 44 72 6f 70 } //01 00  GerarScriptsDrop
		$a_01_12 = {47 65 74 4c 69 73 74 52 65 70 6c 61 63 65 44 6c 6c } //01 00  GetListReplaceDll
		$a_01_13 = {56 65 72 69 66 69 63 61 46 6f 72 65 69 67 6e 4b 65 79 73 } //01 00  VerificaForeignKeys
		$a_01_14 = {6c 62 6c 63 6f 6d 70 75 74 61 64 6f 72 72 65 73 70 6f 6e 73 61 76 65 6c } //01 00  lblcomputadorresponsavel
		$a_01_15 = {74 78 74 55 73 65 72 5f 56 61 6c 69 64 61 74 65 64 } //01 00  txtUser_Validated
		$a_01_16 = {56 65 72 69 66 69 63 61 56 65 72 73 61 6f 50 6c 75 67 69 6e } //00 00  VerificaVersaoPlugin
	condition:
		any of ($a_*)
 
}