
rule MonitoringTool_Win32_SCKeyLog{
	meta:
		description = "MonitoringTool:Win32/SCKeyLog,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_01_0 = {25 73 5c 25 73 2e 64 6c 6c 00 00 00 61 62 00 00 25 73 5c 25 73 2e 65 78 65 00 00 00 57 4c 45 76 74 55 6e 6c 6f 63 6b 00 } //3
		$a_01_1 = {57 4c 45 76 74 53 74 6f 70 53 63 72 65 65 6e 53 61 76 65 72 } //1 WLEvtStopScreenSaver
		$a_01_2 = {57 4c 45 76 74 53 74 61 72 74 53 63 72 65 65 6e 53 61 76 65 72 } //1 WLEvtStartScreenSaver
		$a_01_3 = {57 4c 45 76 74 53 68 75 74 64 6f 77 6e } //1 WLEvtShutdown
		$a_01_4 = {57 4c 45 76 74 4c 6f 63 6b } //1 WLEvtLock
		$a_01_5 = {49 6d 70 65 72 73 6f 6e 61 74 65 00 41 73 79 6e 63 68 72 6f 6e 6f 75 73 } //3 浉数獲湯瑡e獁湹档潲潮獵
		$a_01_6 = {4b 4c 53 68 61 72 65 64 } //3 KLShared
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3) >=9
 
}
rule MonitoringTool_Win32_SCKeyLog_2{
	meta:
		description = "MonitoringTool:Win32/SCKeyLog,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 "
		
	strings :
		$a_01_0 = {57 4c 45 53 68 75 74 64 6f 77 6e } //1 WLEShutdown
		$a_01_1 = {57 4c 45 53 74 61 72 74 53 63 72 65 65 6e 53 61 76 65 72 } //1 WLEStartScreenSaver
		$a_01_2 = {57 4c 45 53 74 6f 70 53 63 72 65 65 6e 53 61 76 65 72 } //1 WLEStopScreenSaver
		$a_01_3 = {41 43 55 54 45 2f 43 45 44 49 4c 4c 41 } //4 ACUTE/CEDILLA
		$a_01_4 = {41 75 74 6f 4b 69 6c 6c 3a 20 54 68 69 73 20 45 6e 67 69 6e 65 20 77 69 6c 6c 20 64 65 6c 65 74 65 20 69 74 73 65 6c 66 20 61 66 74 65 72 20 25 64 20 64 61 79 73 20 66 72 6f 6d 20 6e 6f 77 2e } //5 AutoKill: This Engine will delete itself after %d days from now.
		$a_01_5 = {57 41 52 4e 49 4e 47 3a 20 4c 41 53 54 20 52 45 50 4f 52 54 20 44 55 45 20 54 4f 20 53 45 4c 46 2d 44 45 4c 45 54 45 } //5 WARNING: LAST REPORT DUE TO SELF-DELETE
		$a_01_6 = {4e 65 78 74 50 61 72 74 5f 30 30 30 5f 30 31 43 31 39 39 32 30 2e 38 33 30 33 32 42 43 37 } //4 NextPart_000_01C19920.83032BC7
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*4+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*4) >=15
 
}
rule MonitoringTool_Win32_SCKeyLog_3{
	meta:
		description = "MonitoringTool:Win32/SCKeyLog,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 1a 00 00 "
		
	strings :
		$a_01_0 = {57 4c 45 76 65 6e 74 4c 6f 67 6f 6e } //1 WLEventLogon
		$a_01_1 = {57 4c 45 76 65 6e 74 53 68 75 74 64 6f 77 6e } //1 WLEventShutdown
		$a_01_2 = {57 4c 45 76 65 6e 74 53 74 61 72 74 53 63 72 65 65 6e 53 61 76 65 72 } //1 WLEventStartScreenSaver
		$a_01_3 = {57 4c 45 76 65 6e 74 53 74 61 72 74 75 70 } //1 WLEventStartup
		$a_01_4 = {57 4c 45 76 65 6e 74 53 74 6f 70 53 63 72 65 65 6e 53 61 76 65 72 } //1 WLEventStopScreenSaver
		$a_01_5 = {57 4c 45 76 65 6e 74 55 6e 6c 6f 63 6b } //1 WLEventUnlock
		$a_01_6 = {25 64 2d 25 6d 2d 25 79 20 25 48 3a 25 4d 3a 25 53 } //2 %d-%m-%y %H:%M:%S
		$a_01_7 = {48 6f 73 74 20 28 75 73 65 72 29 3a 20 25 73 20 28 25 73 29 } //2 Host (user): %s (%s)
		$a_01_8 = {4c 6f 67 20 73 74 61 72 74 65 64 20 61 74 20 25 73 } //2 Log started at %s
		$a_01_9 = {50 72 6f 63 65 73 73 20 65 6e 64 65 64 } //2 Process ended
		$a_01_10 = {50 72 6f 63 65 73 73 20 73 74 61 72 74 65 64 } //2 Process started
		$a_01_11 = {3c 57 49 4e 2d 53 54 41 52 54 3e } //1 <WIN-START>
		$a_01_12 = {3c 57 49 4e 2d 43 54 58 54 3e } //1 <WIN-CTXT>
		$a_01_13 = {3c 4e 55 4d 4c 4f 43 4b 3e } //1 <NUMLOCK>
		$a_01_14 = {3c 53 43 52 4c 4f 43 4b 3e } //1 <SCRLOCK>
		$a_01_15 = {3c 50 52 4e 54 53 43 52 3e } //1 <PRNTSCR>
		$a_01_16 = {3c 43 50 53 4c 4f 43 4b 3e } //1 <CPSLOCK>
		$a_01_17 = {4c 42 55 54 54 4f 4e 44 42 4c 43 4c 4b } //1 LBUTTONDBLCLK
		$a_01_18 = {52 42 55 54 54 4f 4e 43 4c 4b 3e } //1 RBUTTONCLK>
		$a_01_19 = {4d 42 55 54 54 4f 4e 43 4c 4b } //1 MBUTTONCLK
		$a_01_20 = {4d 42 55 54 54 4f 4e 44 42 4c 43 4c 4b } //1 MBUTTONDBLCLK
		$a_01_21 = {55 4e 4b 4d 4f 55 53 45 } //1 UNKMOUSE
		$a_01_22 = {56 74 66 73 21 26 74 21 76 6f 6d 70 64 6c 66 65 21 74 7a 74 75 66 6e } //3 Vtfs!&t!vompdlfe!tztufn
		$a_01_23 = {54 64 73 66 66 6f 74 62 77 66 73 21 74 75 70 71 71 66 65 } //3 Tdsffotbwfs!tupqqfe
		$a_01_24 = {54 7a 74 75 66 6e } //3 Tztufn
		$a_01_25 = {21 74 75 62 73 75 66 65 } //3 !tubsufe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*3+(#a_01_23  & 1)*3+(#a_01_24  & 1)*3+(#a_01_25  & 1)*3) >=15
 
}