
rule HackTool_Win32_Wifidump{
	meta:
		description = "HackTool:Win32/Wifidump,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_80_0 = {2f 2f 73 65 63 75 72 69 74 79 78 70 6c 6f 64 65 64 2e 63 6f 6d 2f 77 69 66 69 2d 70 61 73 73 77 6f 72 64 2d 64 75 6d 70 2e 70 68 70 } ////securityxploded.com/wifi-password-dump.php  1
		$a_80_1 = {57 69 46 69 50 61 73 73 77 6f 72 64 44 75 6d 70 } //WiFiPasswordDump  1
		$a_80_2 = {53 74 61 72 74 57 69 46 69 50 61 73 73 77 6f 72 64 52 65 63 6f 76 65 72 79 } //StartWiFiPasswordRecovery  1
		$a_80_3 = {53 65 63 75 72 69 74 79 58 70 6c 6f 64 65 64 } //SecurityXploded  1
		$a_80_4 = {57 69 46 69 50 61 73 73 77 6f 72 64 53 65 72 76 69 63 65 2e 65 78 65 } //WiFiPasswordService.exe  1
		$a_80_5 = {57 69 46 69 20 50 61 73 73 77 6f 72 64 20 44 65 63 72 79 70 74 6f 72 } //WiFi Password Decryptor  1
		$a_80_6 = {5c 54 65 6d 70 5c 77 69 66 69 5f 6f 75 74 70 75 74 2e 74 78 74 } //\Temp\wifi_output.txt  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=6
 
}