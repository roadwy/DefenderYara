
rule MonitoringTool_AndroidOS_Faceniff{
	meta:
		description = "MonitoringTool:AndroidOS/Faceniff,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 61 63 65 6e 69 66 66 5f 69 6e 74 65 6e 74 } //01 00  faceniff_intent
		$a_01_1 = {66 65 74 63 68 5f 66 61 63 65 62 6f 6f 6b } //01 00  fetch_facebook
		$a_01_2 = {66 65 74 63 68 5f 61 6d 61 7a 6f 6e } //01 00  fetch_amazon
		$a_01_3 = {2d 6a 20 44 4e 41 54 20 2d 70 20 74 63 70 20 2d 2d 64 70 6f 72 74 20 31 33 33 37 20 } //01 00  -j DNAT -p tcp --dport 1337 
		$a_01_4 = {73 6e 69 66 66 69 6e 67 3a 20 61 6c 6c 20 73 65 72 76 69 63 65 73 } //00 00  sniffing: all services
	condition:
		any of ($a_*)
 
}