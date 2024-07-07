
rule MonitoringTool_Win32_SystemSurveillance{
	meta:
		description = "MonitoringTool:Win32/SystemSurveillance,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {50 7f 53 79 73 74 65 6d 20 53 75 72 76 65 69 6c 6c 61 6e 63 65 20 50 72 6f 00 09 4a 00 66 31 39 00 00 00 31 33 32 7f 25 53 59 53 25 7f 00 09 09 00 66 31 36 00 00 00 30 7f 53 59 53 7f 25 57 49 4e 25 00 } //5
		$a_01_1 = {64 6f 77 6e 6c 6f 61 64 73 5c 73 73 70 72 6f 5c 69 6e 74 65 72 6e 65 74 5c 67 70 } //1 downloads\sspro\internet\gp
		$a_01_2 = {53 79 73 74 65 6d 20 53 75 72 76 65 69 6c 6c 61 6e 63 65 20 } //1 System Surveillance 
		$a_01_3 = {41 64 64 49 74 65 6d 28 25 57 49 4e 25 5c 73 73 70 33 32 68 70 2e 63 68 6d 2c 48 65 6c 70 20 4d 61 6e 75 61 6c 2c 25 57 49 4e 25 5c 73 73 70 33 32 68 70 } //1 AddItem(%WIN%\ssp32hp.chm,Help Manual,%WIN%\ssp32hp
		$a_01_4 = {44 65 6c 65 74 65 47 72 6f 75 70 28 53 79 73 74 65 6d 20 53 75 72 76 65 69 6c 6c 61 6e 63 65 20 } //1 DeleteGroup(System Surveillance 
		$a_01_5 = {25 44 45 53 4b 54 4f 50 44 49 52 25 5c 53 79 73 74 65 6d 53 75 72 76 65 69 6c 6c 61 6e 63 65 50 72 6f 2e 68 74 6d } //1 %DESKTOPDIR%\SystemSurveillancePro.htm
		$a_01_6 = {65 6d 61 69 6c 73 6e 61 70 73 68 6f 74 69 6e 74 65 72 76 61 6c 3d 25 49 4e 49 5f 53 53 5f 45 4d 41 49 4c 53 4e 41 50 53 48 4f 54 49 4e 54 45 52 56 41 4c 25 } //1 emailsnapshotinterval=%INI_SS_EMAILSNAPSHOTINTERVAL%
		$a_01_7 = {63 6c 65 61 72 6c 6f 67 73 61 66 74 65 72 65 6d 61 69 6c 3d 25 49 4e 49 5f 4c 4f 47 53 5f 43 4c 45 41 52 4c 4f 47 53 41 46 54 45 52 45 4d 41 49 4c 25 } //1 clearlogsafteremail=%INI_LOGS_CLEARLOGSAFTEREMAIL%
		$a_01_8 = {74 68 65 6e 20 72 65 73 74 61 72 74 20 74 68 65 20 53 79 73 74 65 6d 20 53 75 72 76 65 69 6c 6c 61 6e 63 65 } //1 then restart the System Surveillance
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}