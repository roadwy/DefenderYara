
rule MonitoringTool_AndroidOS_Spyoo_A_xp{
	meta:
		description = "MonitoringTool:AndroidOS/Spyoo.A!xp,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {2f 6c 6f 67 73 2f 73 65 74 73 65 74 74 69 6e 67 2e 61 73 70 78 } //1 /logs/setsetting.aspx
		$a_01_1 = {73 65 6e 64 64 65 76 69 63 65 69 6e 66 6f 2e 61 73 70 78 } //1 senddeviceinfo.aspx
		$a_01_2 = {73 70 79 63 61 6c 6c 6e 75 6d 62 65 72 } //1 spycallnumber
		$a_01_3 = {66 6c 61 67 73 70 79 63 61 6c 6c } //1 flagspycall
		$a_01_4 = {6f 6e 43 61 70 74 75 72 65 53 68 61 72 65 64 45 6c 65 6d 65 6e 74 53 6e 61 70 73 68 6f 74 } //1 onCaptureSharedElementSnapshot
		$a_01_5 = {77 77 77 2e 73 70 79 74 69 63 2e 66 72 } //1 www.spytic.fr
		$a_00_6 = {69 69 74 73 2e 73 65 72 76 69 63 65 2e 53 70 79 6f 6f 53 65 72 76 69 63 65 } //1 iits.service.SpyooService
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}