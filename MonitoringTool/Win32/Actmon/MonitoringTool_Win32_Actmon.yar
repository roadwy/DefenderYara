
rule MonitoringTool_Win32_Actmon{
	meta:
		description = "MonitoringTool:Win32/Actmon,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {8d 4d e4 51 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 08 8d 4d e4 e8 ?? ?? ?? ?? 25 ff 00 00 00 85 c0 74 16 8b f4 6a 00 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 8b f4 68 dc 05 00 00 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? eb b2 } //1
		$a_01_1 = {77 73 63 72 69 70 74 2e 65 78 65 20 62 6f 6f 74 2e 76 62 73 } //1 wscript.exe boot.vbs
		$a_01_2 = {77 73 63 72 69 70 74 00 } //1 獷牣灩t
		$a_01_3 = {57 69 6e 45 78 65 63 } //1 WinExec
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule MonitoringTool_Win32_Actmon_2{
	meta:
		description = "MonitoringTool:Win32/Actmon,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {77 73 6b 72 6e 6c 61 64 2e 64 6c 6c 00 3f 48 6f 6f 6b 5f 53 65 74 32 40 40 59 41 48 48 48 40 5a 00 3f 48 6f 6f 6b 5f 53 65 74 40 40 59 41 48 48 48 40 5a 00 3f 48 6f 6f 6b 5f 53 74 61 72 74 40 40 59 41 48 58 5a 00 3f 68 6f 6f 6b 5f 73 74 61 72 74 5f 63 62 74 40 40 59 41 48 58 5a 00 3f 68 6f 6f 6b 5f 73 74 61 72 74 5f 67 65 74 6d 65 73 73 61 67 65 40 40 59 41 48 58 5a 00 3f 68 6f 6f 6b 5f 73 74 6f 70 40 40 59 41 48 58 5a 00 } //1 獷牫汮摡搮汬㼀潈歯卟瑥䀲奀䡁䡈婀㼀潈歯卟瑥䁀䅙䡈䁈Z䠿潯彫瑓牡䁴奀䡁婘㼀潨歯獟慴瑲损瑢䁀䅙塈Z栿潯彫瑳牡彴敧浴獥慳敧䁀䅙塈Z栿潯彫瑳灯䁀䅙塈Z
		$a_01_1 = {69 73 34 5f 5f 00 00 00 73 79 73 33 30 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule MonitoringTool_Win32_Actmon_3{
	meta:
		description = "MonitoringTool:Win32/Actmon,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 "
		
	strings :
		$a_01_0 = {77 73 6b 72 6e 6c 62 2e 64 6c 6c 00 5f 53 54 5f 48 6f 6f 6b 41 6c 6c 41 70 70 73 40 31 32 00 5f 53 54 5f 52 61 77 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 40 38 00 5f 53 54 5f 52 61 77 4c 6f 61 64 4c 69 62 72 61 72 79 41 40 34 00 } //5
		$a_01_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_2 = {4e 74 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 NtQuerySystemInformation
		$a_01_3 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_5 = {50 53 41 50 49 2e 64 6c 6c } //1 PSAPI.dll
		$a_01_6 = {52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 50 72 6f 63 65 73 73 } //1 RegisterServiceProcess
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=11
 
}
rule MonitoringTool_Win32_Actmon_4{
	meta:
		description = "MonitoringTool:Win32/Actmon,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {77 73 6b 72 6e 6c 61 63 2e 64 6c 6c 00 3f 41 72 65 54 61 73 6b 4b 65 79 73 44 69 73 61 62 6c 65 64 40 40 59 41 48 58 5a 00 3f 47 65 74 48 4b 4c 40 40 59 41 50 41 55 48 4b 4c 5f 5f 40 40 58 5a 00 3f 49 6e 73 74 61 6c 6c 54 61 73 6b 4b 65 79 73 40 40 59 41 48 48 40 5a 00 } //5 獷牫汮捡搮汬㼀牁呥獡䭫祥䑳獩扡敬䁤奀䡁婘㼀敇䡴䱋䁀䅙䅐䡕䱋彟䁀婘㼀湉瑳污呬獡䭫祥䁳奀䡁䁈Z
		$a_01_1 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
		$a_01_2 = {50 6f 6c 69 63 69 65 73 5c 43 6f 6d 64 6c 67 33 32 00 4e 6f 45 6e 74 69 72 65 4e 65 74 77 6f 72 6b 00 } //1 潐楬楣獥䍜浯汤㍧2潎湅楴敲敎睴牯k
		$a_01_3 = {50 6f 6c 69 63 69 65 73 5c 4e 65 74 77 6f 72 6b 00 00 4e 6f 43 6c 6f 73 65 00 4e 6f 52 65 63 65 6e 74 44 6f 63 73 48 69 73 74 6f 72 79 00 4e 6f 4e 65 74 43 6f 6e 6e 65 63 74 44 69 73 63 6f 6e 6e 65 63 74 00 00 52 65 73 74 72 69 63 74 52 75 6e 00 4e 6f 44 72 69 76 65 73 00 00 00 00 4e 6f 52 75 6e } //1
		$a_01_4 = {5b 6f 70 65 6e 28 22 25 31 22 29 5d } //1 [open("%1")]
		$a_01_5 = {25 73 5c 73 68 65 6c 6c 5c 70 72 69 6e 74 74 6f 5c 25 73 } //1 %s\shell\printto\%s
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}
rule MonitoringTool_Win32_Actmon_5{
	meta:
		description = "MonitoringTool:Win32/Actmon,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 09 00 0a 00 00 "
		
	strings :
		$a_00_0 = {77 73 6b 72 6e 6c } //1 wskrnl
		$a_00_1 = {5b 46 34 5d 00 00 00 00 5b 46 33 5d 00 00 00 00 5b 46 32 5d 00 00 00 00 5b 46 31 5d 00 00 00 00 5b 41 4c 54 5d 00 00 00 5b 4d 55 4c 54 49 50 4c 59 5d 00 00 5b 43 54 52 4c 5d } //1
		$a_00_2 = {45 6d 61 69 6c 54 6f 00 59 4f 55 52 2d 45 4d 41 49 4c 40 2d 48 45 52 45 2d 2e 43 4f 4d 00 } //1 浅楡呬o余剕䔭䅍䱉ⵀ䕈䕒⸭佃M
		$a_00_3 = {4c 6f 67 67 69 6e 67 20 65 6e 67 69 6e 65 20 73 74 6f 70 70 65 64 } //1 Logging engine stopped
		$a_00_4 = {50 77 64 41 63 74 4d 6f 6e 48 61 73 68 } //1 PwdActMonHash
		$a_02_5 = {5c 5c 41 64 6d 69 6e 2d 50 43 5c [0-08] 52 65 70 6f 72 74 73 5c } //1
		$a_00_6 = {3c 41 63 74 4d 6f 6e 50 72 6f 35 40 61 63 74 6d 6f 6e 70 72 6f 2e 63 6f 6d 3e } //1 <ActMonPro5@actmonpro.com>
		$a_00_7 = {45 78 69 74 69 6e 67 20 53 74 6f 70 50 72 6f 63 65 73 73 28 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 22 29 20 77 69 74 68 20 66 61 69 6c 75 72 65 } //1 Exiting StopProcess("explorer.exe") with failure
		$a_00_8 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
		$a_00_9 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 4e 65 74 77 6f 72 6b } //1 Software\Microsoft\Windows\CurrentVersion\Policies\Network
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=9
 
}
rule MonitoringTool_Win32_Actmon_6{
	meta:
		description = "MonitoringTool:Win32/Actmon,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0d 00 0b 00 00 "
		
	strings :
		$a_02_0 = {41 63 74 4d 6f 6e [0-16] 4d 6f 6e 69 74 6f 72 } //10
		$a_00_1 = {5b 46 34 5d 00 00 00 00 5b 46 33 5d 00 00 00 00 5b 46 32 5d 00 00 00 00 5b 46 31 5d 00 00 00 00 5b 41 4c 54 5d 00 00 00 5b 4d 55 4c 54 49 50 4c 59 5d 00 00 5b 43 54 52 4c 5d } //2
		$a_00_2 = {45 6d 61 69 6c 54 6f 00 59 4f 55 52 2d 45 4d 41 49 4c 40 2d 48 45 52 45 2d 2e 43 4f 4d 00 00 00 31 30 30 34 31 30 30 00 53 65 6e 64 54 72 69 67 67 65 72 } //1
		$a_00_3 = {4c 6f 67 67 69 6e 67 20 65 6e 67 69 6e 65 20 73 74 6f 70 70 65 64 } //1 Logging engine stopped
		$a_00_4 = {5c 5c 41 64 6d 69 6e 2d 50 43 5c 41 63 74 4d 6f 6e 52 65 70 6f 72 74 73 5c } //1 \\Admin-PC\ActMonReports\
		$a_00_5 = {50 77 64 41 63 74 4d 6f 6e 48 61 73 68 } //1 PwdActMonHash
		$a_00_6 = {3c 41 63 74 4d 6f 6e 50 72 6f 35 40 61 63 74 6d 6f 6e 70 72 6f 2e 63 6f 6d 3e } //2 <ActMonPro5@actmonpro.com>
		$a_00_7 = {50 6c 65 61 73 65 20 72 65 70 6f 72 74 20 74 6f 20 73 75 70 70 6f 72 74 32 40 41 63 74 4d 6f 6e 2e 63 6f 6d } //1 Please report to support2@ActMon.com
		$a_00_8 = {43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 43 6c 61 73 73 5c 7b 34 44 33 36 45 39 36 42 2d 45 33 32 35 2d 31 31 43 45 2d 42 46 43 31 2d 30 38 30 30 32 42 45 31 30 33 31 38 7d } //1 CurrentControlSet\Control\Class\{4D36E96B-E325-11CE-BFC1-08002BE10318}
		$a_00_9 = {5c 5c 41 64 6d 69 6e 2d 50 43 5c 53 74 61 72 72 52 65 70 6f 72 74 73 5c } //1 \\Admin-PC\StarrReports\
		$a_00_10 = {5c 53 68 61 72 65 64 00 47 6c 6f 62 61 6c 5c 00 3c 44 4f 43 3e 00 00 00 3c 41 50 50 3e 00 00 00 3c 45 58 45 3e } //1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*2+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=13
 
}