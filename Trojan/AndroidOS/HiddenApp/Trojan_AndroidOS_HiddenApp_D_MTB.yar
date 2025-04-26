
rule Trojan_AndroidOS_HiddenApp_D_MTB{
	meta:
		description = "Trojan:AndroidOS/HiddenApp.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 69 6e 67 2e 63 6f 6e 66 69 72 6d 69 64 2e 6e 61 6d 65 2f } //1 ping.confirmid.name/
		$a_01_1 = {26 70 6e 64 72 5f 69 6e 73 74 61 6c 6c 3d 31 } //1 &pndr_install=1
		$a_01_2 = {2f 63 6c 69 65 6e 74 2e 63 6f 6e 66 69 67 2f 3f 61 70 70 3d 70 6e 64 72 32 26 66 6f 72 6d 61 74 3d 6a 73 6f 6e 26 61 64 76 65 72 74 5f 6b 65 79 3d } //1 /client.config/?app=pndr2&format=json&advert_key=
		$a_01_3 = {73 70 64 79 43 6f 6e 6e 65 63 74 69 6f 6e } //1 spdyConnection
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}