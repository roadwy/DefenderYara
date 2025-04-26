
rule MonitoringTool_Win32_TektonIt{
	meta:
		description = "MonitoringTool:Win32/TektonIt,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {2d 64 20 25 61 70 70 64 61 74 61 25 5c 57 69 6e 64 6f 77 73 5c 63 6f 6e 74 72 6f 6c } //10 -d %appdata%\Windows\control
		$a_01_1 = {72 00 75 00 6e 00 2e 00 62 00 61 00 74 00 } //1 run.bat
		$a_01_2 = {62 00 32 00 62 00 32 00 65 00 74 00 65 00 6d 00 70 00 66 00 69 00 6c 00 65 00 } //1 b2b2etempfile
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}
rule MonitoringTool_Win32_TektonIt_2{
	meta:
		description = "MonitoringTool:Win32/TektonIt,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {2c 2f 63 20 62 75 69 6c 64 5c 64 61 74 61 2e 65 78 65 20 2d 70 37 4c 33 34 4d 46 38 34 35 4a 4d 48 59 30 20 2d 64 20 43 3a 5c 4c 6f 67 } //1 ,/c build\data.exe -p7L34MF845JMHY0 -d C:\Log
		$a_03_1 = {b8 10 80 40 00 a3 ?? ?? ?? ?? b8 30 80 40 00 a3 ?? ?? ?? ?? b8 ?? ?? 40 00 a3 ?? ?? ?? ?? b8 10 14 40 00 a3 ?? ?? ?? ?? a0 60 80 40 00 a2 ?? ?? ?? ?? c3 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}