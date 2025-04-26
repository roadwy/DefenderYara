
rule MonitoringTool_MSIL_NetSpyPro{
	meta:
		description = "MonitoringTool:MSIL/NetSpyPro,SIGNATURE_TYPE_PEHSTR_EXT,04 01 fffffff0 00 09 00 00 "
		
	strings :
		$a_01_0 = {4e 65 74 53 70 79 50 72 6f 5c 4e 53 50 72 6f 5c 4e 53 50 72 6f } //100 NetSpyPro\NSPro\NSPro
		$a_01_1 = {77 74 73 6f 66 74 77 61 72 65 2e 63 6f 6d 2e 62 72 2f } //100 wtsoftware.com.br/
		$a_01_2 = {6e 65 74 73 70 79 70 72 6f 2d 61 6a 75 64 61 2e 68 74 6d } //20 netspypro-ajuda.htm
		$a_01_3 = {67 65 74 5f 4e 53 50 72 6f 5f 53 65 72 69 61 6c 57 53 5f 76 61 6c 69 64 61 5f 73 65 72 69 61 6c } //20 get_NSPro_SerialWS_valida_serial
		$a_01_4 = {67 65 74 5f 66 61 63 65 62 6f 6f 6b 32 00 67 65 74 5f 6d 73 6e } //20
		$a_01_5 = {6d 73 6e 73 70 79 2e 63 6f 6d 2e 62 72 2f 61 64 6d 69 6e 2f 76 61 6c 69 64 61 2d 73 65 72 69 61 6c 2e 61 73 6d 78 } //10 msnspy.com.br/admin/valida-serial.asmx
		$a_01_6 = {63 68 6b 4b 65 79 4c 6f 67 67 65 72 5f 43 68 65 63 6b 65 64 43 68 61 6e 67 65 64 } //10 chkKeyLogger_CheckedChanged
		$a_01_7 = {57 65 62 42 6c 6f 63 6b 65 72 5f 43 68 65 63 6b 65 64 43 68 61 6e 67 65 64 } //10 WebBlocker_CheckedChanged
		$a_01_8 = {74 78 74 4b 65 79 4c 6f 67 67 65 72 4b 65 79 57 6f 72 64 73 } //10 txtKeyLoggerKeyWords
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*20+(#a_01_3  & 1)*20+(#a_01_4  & 1)*20+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10) >=240
 
}