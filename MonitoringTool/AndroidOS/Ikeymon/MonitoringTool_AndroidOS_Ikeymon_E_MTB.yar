
rule MonitoringTool_AndroidOS_Ikeymon_E_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Ikeymon.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 65 72 73 69 73 74 65 64 69 6e 73 74 61 6c 6c 61 74 69 6f 6e } //1 persistedinstallation
		$a_01_1 = {43 61 6c 6c 69 6e 67 52 65 63 6f 72 64 5f 53 65 72 76 69 63 65 } //1 CallingRecord_Service
		$a_01_2 = {2f 64 61 74 61 2f 63 6f 6d 2e 77 68 61 74 73 61 70 70 2f 64 61 74 61 62 61 73 65 73 2f } //1 /data/com.whatsapp/databases/
		$a_01_3 = {2f 64 61 74 61 2f 63 6f 6d 2e 76 69 62 65 72 2e 76 6f 69 70 2f 64 61 74 61 62 61 73 65 73 2f } //1 /data/com.viber.voip/databases/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}