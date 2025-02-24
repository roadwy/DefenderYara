
rule Trojan_AndroidOS_MobOk_H{
	meta:
		description = "Trojan:AndroidOS/MobOk.H,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 74 72 61 74 65 67 79 2f 61 70 69 2f 76 31 2f 61 70 6b 2f 75 70 6c 6f 61 64 } //2 strategy/api/v1/apk/upload
		$a_01_1 = {74 72 61 63 65 2e 67 6c 6b 36 6f 70 6b 2e 63 6f 6d } //2 trace.glk6opk.com
		$a_01_2 = {53 6d 61 72 74 5f 4c 69 6e 6b 5f 57 61 69 74 5f 54 69 6d 65 5f 6f 75 74 } //2 Smart_Link_Wait_Time_out
		$a_01_3 = {75 70 64 61 74 65 55 6e 57 69 66 69 43 66 67 } //2 updateUnWifiCfg
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}