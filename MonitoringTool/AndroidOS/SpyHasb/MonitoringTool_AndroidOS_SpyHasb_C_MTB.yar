
rule MonitoringTool_AndroidOS_SpyHasb_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SpyHasb.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 64 69 63 69 6f 6e 61 72 55 52 4c 42 75 66 66 65 72 } //01 00  AdicionarURLBuffer
		$a_01_1 = {6f 6b 72 65 73 70 6f 6e 73 65 2e 74 78 74 } //01 00  okresponse.txt
		$a_01_2 = {61 70 70 73 65 72 76 65 72 33 6c 2e 6e 6f 2d 69 70 2e 62 69 7a 3a 38 30 39 30 2f 53 65 72 76 65 72 47 50 53 } //01 00  appserver3l.no-ip.biz:8090/ServerGPS
		$a_01_3 = {4b 69 64 73 4c 6f 63 61 74 6f 72 } //01 00  KidsLocator
		$a_01_4 = {63 6f 6d 2f 63 6f 6d 70 61 6e 79 33 4c 2f 46 69 6e 64 4d 79 50 68 6f 6e 65 } //00 00  com/company3L/FindMyPhone
	condition:
		any of ($a_*)
 
}