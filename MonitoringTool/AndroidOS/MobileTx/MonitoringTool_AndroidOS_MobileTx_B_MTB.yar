
rule MonitoringTool_AndroidOS_MobileTx_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MobileTx.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 6f 62 69 6c 65 2e 74 78 2e 63 6f 6d 2e 63 6e 3a 38 30 38 31 2f 63 6c 69 65 6e 74 2f 72 65 67 2e 64 6f } //01 00  mobile.tx.com.cn:8081/client/reg.do
		$a_01_1 = {2f 73 64 63 61 72 64 2f 61 70 70 2f 74 78 2f 72 6f 6f 74 } //01 00  /sdcard/app/tx/root
		$a_01_2 = {74 78 63 6f 6e 66 69 67 2f 6d 65 6e 75 2e 6a 73 6f 6e } //01 00  txconfig/menu.json
		$a_01_3 = {67 65 74 50 68 6f 6e 65 6e 75 6d } //00 00  getPhonenum
	condition:
		any of ($a_*)
 
}