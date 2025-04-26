
rule MonitoringTool_Win32_LanAgent{
	meta:
		description = "MonitoringTool:Win32/LanAgent,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0c 00 06 00 00 "
		
	strings :
		$a_02_0 = {6b 65 79 2e 64 61 74 00 ff ff ff ff 0f 00 00 00 73 63 72 65 65 6e 73 68 6f 74 73 2e 64 61 74 00 [0-08] ff ff ff ff 07 00 00 00 61 70 70 2e 64 61 74 00 ff ff ff ff 0d 00 00 00 63 6c 69 70 62 6f 61 72 64 2e 64 61 74 00 00 00 ff ff ff ff 08 00 00 00 70 72 6e 74 2e 64 61 74 } //10
		$a_00_1 = {47 6c 6f 62 61 6c 5c 53 65 74 74 69 6e 67 73 46 69 6c 65 4d 61 70 } //1 Global\SettingsFileMap
		$a_00_2 = {47 6c 6f 62 61 6c 5c 49 6e 66 6f 46 69 6c 65 4d 61 70 41 70 70 } //1 Global\InfoFileMapApp
		$a_00_3 = {47 6c 6f 62 61 6c 5c 49 6e 66 6f 46 49 6c 65 4d 61 70 53 72 76 } //1 Global\InfoFIleMapSrv
		$a_00_4 = {47 6c 6f 62 61 6c 5c 41 63 74 41 63 74 69 6f 6e 55 6e 49 6e 73 74 } //1 Global\ActActionUnInst
		$a_00_5 = {47 6c 6f 62 61 6c 5c 41 63 74 41 63 74 69 6f 6e 44 72 69 76 65 } //1 Global\ActActionDrive
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=12
 
}