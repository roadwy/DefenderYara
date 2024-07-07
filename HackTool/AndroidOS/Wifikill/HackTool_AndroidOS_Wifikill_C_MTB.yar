
rule HackTool_AndroidOS_Wifikill_C_MTB{
	meta:
		description = "HackTool:AndroidOS/Wifikill.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {64 61 74 61 2f 63 6f 6d 2e 74 65 73 74 65 72 2e 77 70 73 77 70 61 74 65 73 74 65 72 } //1 data/com.tester.wpswpatester
		$a_00_1 = {6d 69 73 63 2f 77 69 66 69 2f 77 70 61 5f 73 75 70 70 6c 69 63 61 6e 74 2e 63 6f 6e 66 } //1 misc/wifi/wpa_supplicant.conf
		$a_00_2 = {57 70 73 53 63 61 6e } //1 WpsScan
		$a_00_3 = {63 68 6d 6f 64 20 37 37 37 20 2f 73 79 73 74 65 6d 2f 62 69 6e 2f 77 70 61 5f 63 6c 69 } //1 chmod 777 /system/bin/wpa_cli
		$a_00_4 = {63 6f 6d 2f 74 65 73 74 65 72 2f 77 70 73 77 70 61 74 65 73 74 65 72 2f 53 68 6f 77 50 61 73 73 77 6f 72 64 } //1 com/tester/wpswpatester/ShowPassword
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}