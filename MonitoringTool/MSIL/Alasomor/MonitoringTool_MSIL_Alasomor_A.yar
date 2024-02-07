
rule MonitoringTool_MSIL_Alasomor_A{
	meta:
		description = "MonitoringTool:MSIL/Alasomor.A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0f 00 00 01 00 "
		
	strings :
		$a_01_0 = {5f 00 4b 00 65 00 79 00 62 00 6f 00 61 00 72 00 64 00 5f 00 41 00 63 00 74 00 69 00 76 00 69 00 74 00 79 00 5f 00 } //01 00  _Keyboard_Activity_
		$a_01_1 = {5f 00 53 00 63 00 72 00 65 00 65 00 6e 00 5f 00 41 00 63 00 74 00 69 00 76 00 69 00 74 00 79 00 5f 00 } //01 00  _Screen_Activity_
		$a_01_2 = {5f 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 5f 00 41 00 63 00 74 00 69 00 76 00 69 00 74 00 79 00 5f 00 } //01 00  _Password_Activity_
		$a_01_3 = {47 65 74 43 68 72 6f 6d 65 50 61 73 73 77 6f 72 64 73 } //01 00  GetChromePasswords
		$a_01_4 = {47 65 74 43 6f 6d 6f 64 6f 50 61 73 73 77 6f 72 64 73 } //01 00  GetComodoPasswords
		$a_01_5 = {47 65 74 46 6c 6f 63 6b 50 61 73 73 77 6f 72 64 73 } //01 00  GetFlockPasswords
		$a_01_6 = {47 65 74 4f 70 65 72 61 50 61 73 73 77 6f 72 64 73 } //01 00  GetOperaPasswords
		$a_01_7 = {47 65 74 59 61 6e 64 65 78 50 61 73 73 77 6f 72 64 73 } //01 00  GetYandexPasswords
		$a_01_8 = {47 65 74 49 45 50 61 73 73 77 6f 72 64 73 } //01 00  GetIEPasswords
		$a_01_9 = {47 65 74 4f 75 74 6c 6f 6f 6b 50 61 73 73 77 6f 72 64 73 } //01 00  GetOutlookPasswords
		$a_01_10 = {47 65 74 54 68 75 6e 64 65 72 62 69 72 64 50 61 73 73 77 6f 72 64 73 } //01 00  GetThunderbirdPasswords
		$a_01_11 = {47 65 74 46 69 72 65 66 6f 78 50 61 73 73 77 6f 72 64 73 } //01 00  GetFirefoxPasswords
		$a_01_12 = {53 65 6e 64 4b 65 79 62 6f 61 72 64 52 65 63 6f 72 64 73 } //01 00  SendKeyboardRecords
		$a_01_13 = {53 65 6e 64 50 61 73 73 77 6f 72 64 52 65 63 6f 72 64 73 } //01 00  SendPasswordRecords
		$a_01_14 = {53 65 6e 64 53 63 72 65 65 6e 52 65 63 6f 72 64 73 } //00 00  SendScreenRecords
	condition:
		any of ($a_*)
 
}