
rule MonitoringTool_Win32_GoldenKeylogger{
	meta:
		description = "MonitoringTool:Win32/GoldenKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 4f 4c 44 45 4e 20 4b 45 59 4c 4f 47 47 45 52 } //10 GOLDEN KEYLOGGER
		$a_01_1 = {2d 20 2d 20 44 65 74 61 69 6c 73 20 2d 20 2d } //1 - - Details - -
		$a_01_2 = {50 61 73 73 77 6f 72 64 20 69 6e 20 77 69 6e 64 6f 77 20 22 25 73 22 } //1 Password in window "%s"
		$a_01_3 = {68 74 74 70 3a 2f 2f 73 70 79 61 72 73 65 6e 61 6c 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 72 65 67 2e 70 6c 3f 70 3d 47 4b 4c 26 6b 65 79 3d 25 73 26 76 3d 25 73 26 65 6d 61 69 6c 3d 25 73 } //1 http://spyarsenal.com/cgi-bin/reg.pl?p=GKL&key=%s&v=%s&email=%s
		$a_01_4 = {53 54 41 52 54 20 4c 4f 47 47 49 4e 47 00 53 54 4f 50 20 4c 4f 47 47 49 4e 47 } //1 呓剁⁔佌䝇义G呓偏䰠䝏䥇䝎
		$a_01_5 = {41 4c 4c 20 41 43 54 49 56 49 54 49 45 53 20 4f 4e 20 54 48 49 53 20 53 59 53 54 45 4d 20 41 52 45 20 4d 4f 4e 49 54 4f 52 45 44 2e } //1 ALL ACTIVITIES ON THIS SYSTEM ARE MONITORED.
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=13
 
}