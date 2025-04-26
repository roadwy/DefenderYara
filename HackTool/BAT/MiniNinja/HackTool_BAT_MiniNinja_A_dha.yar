
rule HackTool_BAT_MiniNinja_A_dha{
	meta:
		description = "HackTool:BAT/MiniNinja.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0a 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 42 65 61 63 6f 6e 42 6c 61 63 6b 4c 69 73 74 49 50 } //1 GetBeaconBlackListIP
		$a_01_1 = {69 73 43 6f 6e 6e 65 63 74 54 6f 4c 69 73 74 6e 65 72 } //1 isConnectToListner
		$a_00_2 = {6d 79 62 61 73 65 36 34 5f 64 65 63 6f 64 65 } //1 mybase64_decode
		$a_00_3 = {4d 69 6e 69 50 61 6e 65 6c 48 65 6c 70 65 72 2e 64 6c 6c } //1 MiniPanelHelper.dll
		$a_01_4 = {42 65 61 63 6f 6e 43 6f 6e 74 72 6f 6c 53 65 72 76 65 72 } //1 BeaconControlServer
		$a_01_5 = {53 65 6e 64 42 65 61 63 6f 6e 43 6c 69 65 6e 74 44 61 74 61 54 6f 53 65 72 76 65 72 } //1 SendBeaconClientDataToServer
		$a_01_6 = {44 69 72 65 63 74 43 6f 6e 6e 65 63 74 54 6f 53 65 72 76 65 72 } //1 DirectConnectToServer
		$a_01_7 = {42 65 61 63 6f 6e 48 65 61 72 74 42 65 61 74 } //1 BeaconHeartBeat
		$a_01_8 = {53 65 6e 64 53 65 72 76 65 72 52 65 73 70 6f 6e 73 65 54 6f 42 65 61 63 6f 6e 43 6c 69 65 6e 74 } //1 SendServerResponseToBeaconClient
		$a_01_9 = {48 61 6e 64 6c 65 42 65 61 63 6f 6e 43 6c 69 65 6e 74 52 65 71 75 65 73 74 } //1 HandleBeaconClientRequest
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=7
 
}