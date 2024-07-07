
rule Backdoor_BAT_Zqorat_A{
	meta:
		description = "Backdoor:BAT/Zqorat.A,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 1f 00 00 "
		
	strings :
		$a_80_0 = {5c 5a 52 41 54 5c 51 52 41 54 } //\ZRAT\QRAT  8
		$a_80_1 = {5c 51 52 41 54 5f 43 6c 69 65 6e 74 5c 50 6c 75 67 69 6e 49 6e 74 65 72 66 61 63 65 5c } //\QRAT_Client\PluginInterface\  10
		$a_80_2 = {5c 43 6c 69 65 6e 74 50 6c 75 67 69 6e 49 6e 74 65 72 66 61 63 65 2e 70 64 62 } //\ClientPluginInterface.pdb  2
		$a_80_3 = {41 64 64 54 6f 53 74 61 72 74 75 70 46 61 69 6c 65 64 } //AddToStartupFailed  1
		$a_80_4 = {44 65 6c 65 74 65 4b 65 79 6c 6f 67 67 65 72 4c 6f 67 73 } //DeleteKeyloggerLogs  1
		$a_80_5 = {44 6f 41 73 6b 45 6c 65 76 61 74 65 } //DoAskElevate  1
		$a_80_6 = {44 6f 43 68 65 63 6b 55 70 6c 6f 61 64 54 6f 6f 6c } //DoCheckUploadTool  1
		$a_80_7 = {44 6f 43 68 65 63 6b 55 70 6c 6f 61 64 54 6f 6f 6c 52 65 73 70 6f 6e 73 65 } //DoCheckUploadToolResponse  1
		$a_80_8 = {44 6f 43 6c 69 65 6e 74 44 69 73 63 6f 6e 6e 65 63 74 } //DoClientDisconnect  1
		$a_80_9 = {44 6f 43 6c 69 65 6e 74 52 65 63 6f 6e 6e 65 63 74 } //DoClientReconnect  1
		$a_80_10 = {44 6f 43 6c 69 65 6e 74 55 6e 69 6e 73 74 61 6c 6c } //DoClientUninstall  1
		$a_80_11 = {44 6f 43 6c 69 65 6e 74 55 70 64 61 74 65 } //DoClientUpdate  1
		$a_80_12 = {44 6f 44 65 6d 61 6e 64 } //DoDemand  1
		$a_80_13 = {44 6f 65 73 57 69 6e 33 32 4d 65 74 68 6f 64 45 78 69 73 74 } //DoesWin32MethodExist  1
		$a_80_14 = {44 6f 45 78 74 65 72 6e 61 6c 54 6f 6f 6c 53 74 61 72 74 } //DoExternalToolStart  1
		$a_80_15 = {44 6f 45 78 74 65 72 6e 61 6c 54 6f 6f 6c 53 74 61 72 74 52 65 73 70 6f 6e 73 65 } //DoExternalToolStartResponse  1
		$a_80_16 = {44 6f 45 78 74 65 72 6e 61 6c 54 6f 6f 6c 53 74 6f 70 } //DoExternalToolStop  1
		$a_80_17 = {44 6f 4b 65 79 62 6f 61 72 64 45 76 65 6e 74 } //DoKeyboardEvent  1
		$a_80_18 = {44 6f 52 75 6e 55 70 6c 6f 61 64 54 6f 6f 6c } //DoRunUploadTool  1
		$a_80_19 = {44 6f 53 65 6e 64 55 70 6c 6f 61 64 43 6f 6e 66 69 67 } //DoSendUploadConfig  1
		$a_80_20 = {44 6f 53 68 75 74 64 6f 77 6e 41 63 74 69 6f 6e } //DoShutdownAction  1
		$a_80_21 = {44 6f 55 70 6c 6f 61 64 46 69 6c 65 } //DoUploadFile  1
		$a_80_22 = {44 6f 56 69 73 69 74 57 65 62 73 69 74 65 } //DoVisitWebsite  1
		$a_80_23 = {47 65 74 49 6e 73 74 61 6c 6c 65 64 41 70 70 } //GetInstalledApp  1
		$a_80_24 = {47 65 74 4b 65 79 6c 6f 67 67 65 72 4c 6f 67 73 } //GetKeyloggerLogs  1
		$a_80_25 = {48 61 6e 64 6c 65 49 6e 73 74 61 6c 6c 50 61 63 6b 65 74 } //HandleInstallPacket  1
		$a_80_26 = {49 73 4d 6f 75 73 65 4b 65 79 44 6f 77 6e } //IsMouseKeyDown  1
		$a_80_27 = {49 73 4d 6f 75 73 65 4b 65 79 55 70 } //IsMouseKeyUp  1
		$a_80_28 = {76 69 72 74 75 61 6c 4b 65 79 43 6f 64 65 } //virtualKeyCode  1
		$a_80_29 = {56 69 73 74 61 4f 72 48 69 67 68 65 72 } //VistaOrHigher  1
		$a_80_30 = {58 70 4f 72 48 69 67 68 65 72 } //XpOrHigher  1
	condition:
		((#a_80_0  & 1)*8+(#a_80_1  & 1)*10+(#a_80_2  & 1)*2+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1+(#a_80_15  & 1)*1+(#a_80_16  & 1)*1+(#a_80_17  & 1)*1+(#a_80_18  & 1)*1+(#a_80_19  & 1)*1+(#a_80_20  & 1)*1+(#a_80_21  & 1)*1+(#a_80_22  & 1)*1+(#a_80_23  & 1)*1+(#a_80_24  & 1)*1+(#a_80_25  & 1)*1+(#a_80_26  & 1)*1+(#a_80_27  & 1)*1+(#a_80_28  & 1)*1+(#a_80_29  & 1)*1+(#a_80_30  & 1)*1) >=20
 
}