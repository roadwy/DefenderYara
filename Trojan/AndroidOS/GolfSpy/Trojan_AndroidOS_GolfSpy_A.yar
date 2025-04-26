
rule Trojan_AndroidOS_GolfSpy_A{
	meta:
		description = "Trojan:AndroidOS/GolfSpy.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {43 6f 6d 6d 75 6e 69 63 61 74 6f 72 53 65 72 76 69 63 65 } //1 CommunicatorService
		$a_00_1 = {54 6f 6f 6c 73 4e 61 76 69 67 61 74 65 53 65 72 76 69 63 65 } //1 ToolsNavigateService
		$a_00_2 = {43 61 6d 65 72 61 20 50 69 63 74 75 72 65 73 20 52 65 63 65 69 76 65 64 20 69 6e 20 4c 61 73 74 20 37 20 44 61 79 73 } //1 Camera Pictures Received in Last 7 Days
		$a_00_3 = {61 75 64 69 6f 52 65 63 6f 72 64 65 72 2e 73 74 61 72 74 56 6f 69 63 65 52 65 63 6f 72 64 65 72 } //1 audioRecorder.startVoiceRecorder
		$a_00_4 = {44 65 76 69 63 65 20 69 73 45 6d 75 6c 61 74 6f 72 21 21 21 21 } //1 Device isEmulator!!!!
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}