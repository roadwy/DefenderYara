
rule MonitoringTool_AndroidOS_Cerberus_E_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Cerberus.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 73 69 6d 69 6e 66 6f } //05 00  sendsiminfo
		$a_01_1 = {43 65 72 62 65 72 75 73 53 65 72 76 69 63 65 } //01 00  CerberusService
		$a_01_2 = {63 6f 6d 6d 2f 73 65 6e 64 74 72 61 63 6b 2e 70 68 70 } //01 00  comm/sendtrack.php
		$a_01_3 = {53 54 41 52 54 5f 54 52 41 43 4b 49 4e 47 } //05 00  START_TRACKING
		$a_01_4 = {63 65 72 62 65 72 75 73 61 70 70 2e 63 6f 6d 2f 63 6f 6d 6d 2f 73 65 6e 64 70 69 63 74 75 72 65 2e 70 68 70 } //01 00  cerberusapp.com/comm/sendpicture.php
		$a_01_5 = {73 65 6e 64 6c 6f 63 61 74 69 6f 6e } //00 00  sendlocation
	condition:
		any of ($a_*)
 
}