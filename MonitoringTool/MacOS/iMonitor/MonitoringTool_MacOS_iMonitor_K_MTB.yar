
rule MonitoringTool_MacOS_iMonitor_K_MTB{
	meta:
		description = "MonitoringTool:MacOS/iMonitor.K!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_00_0 = {2f 55 73 65 72 73 2f 69 6d 6f 6e 69 74 6f 72 2f 44 65 73 6b 74 6f 70 2f 45 41 4d 2f 69 6d 6f 6e 69 74 6f 72 2f 69 6d 6f 6e 69 74 6f 72 2f } //1 /Users/imonitor/Desktop/EAM/imonitor/imonitor/
		$a_00_1 = {2f 6c 69 62 72 61 72 79 2f 69 6d 6f 6e 69 74 6f 72 2f 6b 65 79 73 74 72 6f 6b 65 73 2e 63 66 67 } //1 /library/imonitor/keystrokes.cfg
		$a_00_2 = {25 40 2f 6b 65 79 77 6e 64 6c 6f 67 2e 63 66 67 } //1 %@/keywndlog.cfg
		$a_00_3 = {25 40 2f 66 69 6c 65 6c 6f 67 2e 63 66 67 } //1 %@/filelog.cfg
		$a_00_4 = {25 40 2f 63 6c 69 70 62 6f 61 72 64 2e 63 66 67 } //1 %@/clipboard.cfg
		$a_00_5 = {69 73 69 6d 6f 6e 69 74 6f 72 72 75 6e 6e 69 6e 67 } //1 isimonitorrunning
		$a_00_6 = {75 70 64 61 74 65 65 61 6d 73 65 72 76 65 72 69 70 } //1 updateeamserverip
		$a_00_7 = {2f 6c 69 62 72 61 72 79 2f 69 6d 6f 6e 69 74 6f 72 2f 6c 61 73 74 70 69 6e 67 2e 74 78 74 } //1 /library/imonitor/lastping.txt
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=6
 
}