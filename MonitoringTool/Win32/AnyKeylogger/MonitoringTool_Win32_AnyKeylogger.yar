
rule MonitoringTool_Win32_AnyKeylogger{
	meta:
		description = "MonitoringTool:Win32/AnyKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_00_0 = {6b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 5c 00 } //10 keylogger\
		$a_01_1 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 00 } //5
		$a_01_2 = {5b 00 45 00 6e 00 74 00 65 00 72 00 5d 00 } //1 [Enter]
		$a_01_3 = {26 65 6d 61 69 6c 74 6f 3d 00 } //1 攦慭汩潴=
		$a_01_4 = {5b 00 41 00 4c 00 54 00 } //1 [ALT
		$a_01_5 = {5b 00 46 00 31 00 } //1 [F1
		$a_01_6 = {7b 00 73 00 68 00 69 00 66 00 74 00 7d 00 } //1 {shift}
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=16
 
}