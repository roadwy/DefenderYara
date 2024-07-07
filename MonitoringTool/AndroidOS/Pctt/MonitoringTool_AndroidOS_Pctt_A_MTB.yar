
rule MonitoringTool_AndroidOS_Pctt_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Pctt.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_01_0 = {4b 65 79 53 74 72 6f 6b 65 50 61 79 4c 6f 61 64 } //1 KeyStrokePayLoad
		$a_01_1 = {50 43 20 54 61 74 74 6c 65 74 61 6c 65 } //1 PC Tattletale
		$a_01_2 = {52 65 6d 6f 74 65 4d 6f 6e 69 74 6f 72 69 6e 67 } //1 RemoteMonitoring
		$a_01_3 = {50 52 45 56 45 4e 54 5f 55 4e 49 4e 53 54 41 4c 4c } //1 PREVENT_UNINSTALL
		$a_01_4 = {6c 61 73 74 47 50 53 43 61 6c 6c 44 61 74 65 54 69 6d 65 73 74 61 6d 70 } //1 lastGPSCallDateTimestamp
		$a_00_5 = {63 6f 6d 2e 61 76 69 2e 73 63 62 61 73 65 } //10 com.avi.scbase
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*10) >=14
 
}