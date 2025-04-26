
rule MonitoringTool_AndroidOS_Spy24_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Spy24.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 73 70 79 32 34 2f 77 69 66 69 2f 72 65 63 6f 72 64 41 75 64 69 6f 2f } //2 /spy24/wifi/recordAudio/
		$a_00_1 = {67 65 74 4c 61 73 74 49 6e 73 74 61 67 72 61 6d 4d 65 73 73 61 67 65 } //1 getLastInstagramMessage
		$a_00_2 = {73 74 61 72 74 53 63 68 75 6c 65 72 } //1 startSchuler
		$a_00_3 = {6c 6f 63 61 74 69 6f 6e 46 72 6f 6d 53 4d 53 } //1 locationFromSMS
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}