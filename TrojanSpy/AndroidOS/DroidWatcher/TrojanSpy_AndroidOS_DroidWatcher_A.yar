
rule TrojanSpy_AndroidOS_DroidWatcher_A{
	meta:
		description = "TrojanSpy:AndroidOS/DroidWatcher.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 41 6e 64 72 6f 69 64 2f 64 61 74 61 2f 71 2e 73 68 } //1 /Android/data/q.sh
		$a_00_1 = {44 57 5f 43 6c 69 62 6f 61 72 64 } //1 DW_Cliboard
		$a_00_2 = {47 50 53 20 6d 70 64 75 6c 65 20 6e 6f 74 20 69 73 47 70 73 54 72 61 63 6b 69 6e 67 45 6e 61 62 6c 65 64 } //1 GPS mpdule not isGpsTrackingEnabled
		$a_00_3 = {54 47 50 5f 45 4e 41 42 4c 45 44 } //1 TGP_ENABLED
		$a_00_4 = {57 69 6e 64 4d 6f 64 75 6c 65 2e 53 68 6f 74 65 72 5f 2e 53 63 72 65 65 6e 73 68 6f 74 53 65 72 76 69 63 65 } //1 WindModule.Shoter_.ScreenshotService
		$a_00_5 = {77 68 61 74 73 20 61 70 70 20 67 65 74 20 6e 65 77 20 63 68 61 74 74 2e 2e 69 6e 68 } //1 whats app get new chatt..inh
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}