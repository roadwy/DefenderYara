
rule TrojanSpy_AndroidOS_Pegasus_D{
	meta:
		description = "TrojanSpy:AndroidOS/Pegasus.D,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {68 61 73 50 72 6f 78 79 42 65 65 6e 43 6c 65 61 72 65 64 } //1 hasProxyBeenCleared
		$a_00_1 = {4e 65 74 77 6f 72 6b 57 69 6e 64 6f 77 53 69 6d } //1 NetworkWindowSim
		$a_00_2 = {6e 65 74 77 6f 72 6b 52 65 63 69 76 65 72 48 61 6e 64 6c 65 72 } //1 networkReciverHandler
		$a_00_3 = {61 64 64 52 65 63 6f 72 64 46 69 6c 65 54 6f 50 72 6f 64 75 63 74 73 44 42 } //1 addRecordFileToProductsDB
		$a_00_4 = {61 67 65 6e 74 45 78 66 69 6c 74 72 61 74 69 6f 6e 48 65 61 64 65 72 } //1 agentExfiltrationHeader
		$a_00_5 = {63 6f 6d 2e 6e 65 74 77 6f 72 6b 2e 61 6e 64 72 6f 69 64 } //1 com.network.android
		$a_00_6 = {41 6e 64 72 6f 69 64 43 61 6c 6c 44 69 72 65 63 74 57 61 74 63 68 65 72 } //1 AndroidCallDirectWatcher
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}