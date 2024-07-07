
rule MonitoringTool_AndroidOS_Avancar_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Avancar.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 6d 6f 6e 69 74 6f 72 2f 73 65 6e 64 6d 61 69 6c 2e 70 68 70 } //1 /monitor/sendmail.php
		$a_01_1 = {57 69 70 65 49 63 6f 6e } //1 WipeIcon
		$a_00_2 = {2f 6d 6f 6e 69 74 6f 72 2f 61 6e 64 73 61 76 65 2e 70 68 70 } //1 /monitor/andsave.php
		$a_01_3 = {55 70 64 49 6d 67 43 6f 6e 74 61 63 74 73 } //1 UpdImgContacts
		$a_00_4 = {2f 6d 6f 6e 69 74 6f 72 2f 67 65 74 63 66 67 2e 70 68 70 } //1 /monitor/getcfg.php
		$a_00_5 = {63 6f 6d 2e 64 65 76 69 63 65 6d 6f 6e 2e 73 65 72 76 69 63 65 73 2e 6d 61 69 6e } //1 com.devicemon.services.main
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}