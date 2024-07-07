
rule Trojan_AndroidOS_SpyAgent_XYZ{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.XYZ,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 65 74 53 6d 73 62 6f 64 79 } //1 setSmsbody
		$a_01_1 = {4c 63 6f 6d 2f 61 6d 61 70 2f 61 70 69 2f 6c 6f 63 61 74 69 6f 6e 2f 41 50 53 53 65 72 76 69 63 65 } //1 Lcom/amap/api/location/APSService
		$a_01_2 = {63 6c 6f 75 64 2f 57 65 62 41 63 74 69 76 69 74 79 } //1 cloud/WebActivity
		$a_01_3 = {6d 61 72 6b 48 6f 73 74 4e 61 6d 65 46 61 69 6c 65 64 } //1 markHostNameFailed
		$a_01_4 = {69 70 76 36 20 72 65 71 75 65 73 74 20 69 73 } //1 ipv6 request is
		$a_01_5 = {79 69 79 69 2e 71 69 } //1 yiyi.qi
		$a_01_6 = {21 21 21 66 69 6e 69 73 68 2d } //1 !!!finish-
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}