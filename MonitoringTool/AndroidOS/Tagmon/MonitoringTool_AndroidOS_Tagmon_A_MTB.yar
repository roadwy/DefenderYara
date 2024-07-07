
rule MonitoringTool_AndroidOS_Tagmon_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Tagmon.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {45 6d 75 6c 61 74 6f 72 44 65 74 65 63 74 6f 72 } //1 EmulatorDetector
		$a_01_1 = {63 68 6b 57 68 61 74 73 41 70 70 } //1 chkWhatsApp
		$a_01_2 = {2f 61 6c 74 65 72 61 73 65 6e 68 61 2e 70 68 70 } //1 /alterasenha.php
		$a_01_3 = {63 6f 6d 2e 69 73 77 73 63 2e 73 6d 61 63 6b 64 65 6d 6f 2e 63 6f 6e 74 61 63 74 } //1 com.iswsc.smackdemo.contact
		$a_01_4 = {63 6f 6e 74 61 63 74 56 6f 4c 69 73 74 } //1 contactVoList
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}