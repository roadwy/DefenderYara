
rule Trojan_Win64_Ursnif_CC_MTB{
	meta:
		description = "Trojan:Win64/Ursnif.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 0a 00 00 03 00 "
		
	strings :
		$a_81_0 = {57 69 6e 48 74 74 70 4f 70 65 6e 52 65 71 75 65 73 74 } //03 00  WinHttpOpenRequest
		$a_81_1 = {57 69 6e 48 74 74 70 52 65 61 64 44 61 74 61 } //03 00  WinHttpReadData
		$a_81_2 = {57 69 6e 48 74 74 70 41 64 64 52 65 71 75 65 73 74 48 65 61 64 65 72 73 } //03 00  WinHttpAddRequestHeaders
		$a_81_3 = {53 65 74 75 70 44 69 47 65 74 44 65 76 69 63 65 52 65 67 69 73 74 72 79 50 72 6f 70 65 72 74 79 41 } //03 00  SetupDiGetDeviceRegistryPropertyA
		$a_81_4 = {41 56 49 46 69 6c 65 45 78 69 74 } //03 00  AVIFileExit
		$a_81_5 = {41 56 49 46 69 6c 65 4f 70 65 6e 57 } //03 00  AVIFileOpenW
		$a_81_6 = {74 75 72 62 6f 73 2e 64 6c 6c } //03 00  turbos.dll
		$a_81_7 = {4d 53 56 43 63 76 69 64 4d 52 4c 45 } //03 00  MSVCcvidMRLE
		$a_81_8 = {43 6f 6e 76 65 72 74 53 74 72 69 6e 67 53 65 63 75 72 69 74 79 44 65 73 63 72 69 70 74 6f 72 54 6f 53 65 63 75 72 69 74 79 44 65 73 63 72 69 70 74 6f 72 41 } //03 00  ConvertStringSecurityDescriptorToSecurityDescriptorA
		$a_81_9 = {53 68 65 6c 6c 45 78 65 63 75 74 65 57 } //00 00  ShellExecuteW
	condition:
		any of ($a_*)
 
}