
rule Trojan_BAT_XWorm_DX_MTB{
	meta:
		description = "Trojan:BAT/XWorm.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_81_0 = {41 63 74 69 76 61 74 65 50 6f 6e 67 } //1 ActivatePong
		$a_81_1 = {69 73 44 69 73 63 6f 6e 6e 65 63 74 65 64 } //1 isDisconnected
		$a_81_2 = {52 75 6e 41 6e 74 69 41 6e 61 6c 79 73 69 73 } //1 RunAntiAnalysis
		$a_81_3 = {55 53 42 4e 4d } //1 USBNM
		$a_81_4 = {53 70 72 65 61 64 } //1 Spread
		$a_81_5 = {43 6f 6e 6e 65 63 74 53 65 72 76 65 72 } //1 ConnectServer
		$a_81_6 = {44 44 6f 73 } //1 DDos
		$a_81_7 = {49 4e 44 41 54 45 } //1 INDATE
		$a_81_8 = {42 65 67 69 6e 43 6f 6e 6e 65 63 74 } //1 BeginConnect
		$a_81_9 = {63 61 70 47 65 74 44 72 69 76 65 72 44 65 73 63 72 69 70 74 69 6f 6e 41 } //1 capGetDriverDescriptionA
		$a_81_10 = {63 61 70 43 72 65 61 74 65 43 61 70 74 75 72 65 57 69 6e 64 6f 77 41 } //1 capCreateCaptureWindowA
		$a_81_11 = {53 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 49 73 43 72 69 74 69 63 61 6c } //1 SetCurrentProcessIsCritical
		$a_81_12 = {43 72 69 74 69 63 61 6c 50 72 6f 63 65 73 73 65 73 5f 44 69 73 61 62 6c 65 } //1 CriticalProcesses_Disable
		$a_81_13 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1) >=14
 
}