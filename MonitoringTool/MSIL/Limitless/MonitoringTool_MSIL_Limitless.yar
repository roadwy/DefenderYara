
rule MonitoringTool_MSIL_Limitless{
	meta:
		description = "MonitoringTool:MSIL/Limitless,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 00 45 00 42 00 53 00 49 00 54 00 45 00 4c 00 49 00 4e 00 4b 00 } //1 WEBSITELINK
		$a_01_1 = {46 00 61 00 69 00 6c 00 65 00 64 00 20 00 54 00 6f 00 20 00 53 00 74 00 61 00 72 00 74 00 20 00 53 00 65 00 6e 00 64 00 69 00 6e 00 67 00 20 00 54 00 68 00 72 00 65 00 61 00 64 00 2e 00 } //1 Failed To Start Sending Thread.
		$a_01_2 = {2d 00 2d 00 3a 00 3a 00 5d 00 } //1 --::]
		$a_01_3 = {53 00 65 00 74 00 46 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //1 SetFpassword
		$a_01_4 = {46 00 54 00 50 00 55 00 70 00 6c 00 6f 00 61 00 64 00 } //1 FTPUpload
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule MonitoringTool_MSIL_Limitless_2{
	meta:
		description = "MonitoringTool:MSIL/Limitless,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4e 00 6f 00 20 00 4c 00 6f 00 67 00 73 00 20 00 57 00 65 00 72 00 65 00 20 00 52 00 65 00 63 00 6f 00 72 00 64 00 65 00 64 00 2e 00 20 00 4e 00 6f 00 74 00 20 00 53 00 65 00 6e 00 64 00 69 00 6e 00 67 00 20 00 41 00 20 00 4c 00 6f 00 67 00 2e 00 2e 00 2e 00 } //1 No Logs Were Recorded. Not Sending A Log...
		$a_01_1 = {2d 00 2d 00 3a 00 3a 00 5d 00 } //1 --::]
		$a_01_2 = {4c 00 69 00 6d 00 69 00 74 00 6c 00 65 00 73 00 73 00 20 00 4c 00 6f 00 67 00 67 00 65 00 72 00 20 00 3a 00 20 00 3a 00 } //1 Limitless Logger : :
		$a_01_3 = {46 00 54 00 50 00 55 00 70 00 6c 00 6f 00 61 00 64 00 } //1 FTPUpload
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule MonitoringTool_MSIL_Limitless_3{
	meta:
		description = "MonitoringTool:MSIL/Limitless,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 00 61 00 69 00 6c 00 65 00 64 00 20 00 54 00 6f 00 20 00 53 00 74 00 61 00 72 00 74 00 20 00 53 00 65 00 6e 00 64 00 69 00 6e 00 67 00 20 00 54 00 68 00 72 00 65 00 61 00 64 00 2e 00 } //1 Failed To Start Sending Thread.
		$a_01_1 = {4c 00 69 00 6d 00 69 00 74 00 6c 00 65 00 73 00 73 00 20 00 4c 00 6f 00 67 00 67 00 65 00 72 00 20 00 3a 00 20 00 3a 00 20 00 4b 00 65 00 79 00 62 00 6f 00 61 00 72 00 64 00 } //1 Limitless Logger : : Keyboard
		$a_01_2 = {4b 00 65 00 79 00 62 00 6f 00 61 00 72 00 64 00 20 00 52 00 65 00 63 00 6f 00 72 00 64 00 73 00 20 00 3a 00 20 00 3a 00 } //1 Keyboard Records : :
		$a_01_3 = {73 63 72 65 65 6e 73 68 6f 74 43 6f 75 6e 74 00 63 61 70 74 75 72 65 53 63 72 65 65 6e 00 } //1 捳敲湥桳瑯潃湵t慣瑰牵卥牣敥n
		$a_01_4 = {63 72 65 61 74 65 4c 6f 77 4c 65 76 65 6c 4b 65 79 62 6f 61 72 64 48 6f 6f 6b } //1 createLowLevelKeyboardHook
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}