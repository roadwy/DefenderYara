
rule Backdoor_AndroidOS_Vsas_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/Vsas.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 61 76 65 41 70 70 44 61 74 61 } //1 saveAppData
		$a_01_1 = {2f 64 70 69 2f 67 65 74 74 61 73 6b 2e 70 68 70 } //1 /dpi/gettask.php
		$a_01_2 = {72 65 73 70 5f 69 6e 66 6f } //1 resp_info
		$a_00_3 = {4c 63 6f 6d 2f 76 73 61 61 73 2f 70 } //1 Lcom/vsaas/p
		$a_00_4 = {61 70 70 2e 77 61 70 78 2e 63 6e } //1 app.wapx.cn
		$a_01_5 = {4d 6f 6e 69 74 6f 72 53 65 72 76 69 63 65 } //1 MonitorService
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}