
rule MonitoringTool_MSIL_Farri{
	meta:
		description = "MonitoringTool:MSIL/Farri,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 00 61 00 72 00 72 00 69 00 20 00 6b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 } //1 Farri keylogger
		$a_01_1 = {54 00 65 00 73 00 74 00 20 00 45 00 6d 00 61 00 69 00 6c 00 20 00 49 00 44 00 20 00 26 00 20 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //1 Test Email ID & Password
		$a_01_2 = {5c 00 53 00 65 00 72 00 76 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 \Server.exe
		$a_01_3 = {73 00 6d 00 74 00 70 00 2e 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //1 smtp.gmail.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}