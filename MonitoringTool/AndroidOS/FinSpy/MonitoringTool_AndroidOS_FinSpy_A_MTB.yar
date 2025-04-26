
rule MonitoringTool_AndroidOS_FinSpy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/FinSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {4d 6f 64 75 6c 65 20 53 70 79 20 43 61 6c 6c } //1 Module Spy Call
		$a_00_1 = {54 6c 76 54 79 70 65 4d 6f 62 69 6c 65 54 61 72 67 65 74 45 78 74 65 6e 64 65 64 48 65 61 72 74 42 65 61 74 56 31 30 } //1 TlvTypeMobileTargetExtendedHeartBeatV10
		$a_00_2 = {54 6c 76 54 79 70 65 4d 6f 62 69 6c 65 54 72 61 63 6b 69 6e 67 43 6f 6e 66 69 67 52 61 77 } //1 TlvTypeMobileTrackingConfigRaw
		$a_00_3 = {54 6c 76 54 79 70 65 4d 6f 62 69 6c 65 4c 6f 67 67 69 6e 67 4d 65 74 61 49 6e 66 6f } //1 TlvTypeMobileLoggingMetaInfo
		$a_00_4 = {54 6c 76 54 79 70 65 4d 6f 62 69 6c 65 50 68 6f 6e 65 43 61 6c 6c 4c 6f 67 73 44 61 74 61 } //1 TlvTypeMobilePhoneCallLogsData
		$a_00_5 = {52 65 63 6f 72 64 73 20 41 6c 6c 20 53 6d 73 } //1 Records All Sms
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}