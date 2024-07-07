
rule Trojan_AndroidOS_Hypay_A_xp{
	meta:
		description = "Trojan:AndroidOS/Hypay.A!xp,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 6d 70 75 73 68 5f 6c 62 78 2e 6a 61 72 } //1 dmpush_lbx.jar
		$a_00_1 = {3a 2f 2f 31 38 32 2e 39 32 2e 36 35 2e 32 34 37 3a 37 30 38 31 2f 42 61 69 64 75 4d 76 5f 57 61 6e 67 } //1 ://182.92.65.247:7081/BaiduMv_Wang
		$a_01_2 = {44 65 6d 6f 48 65 65 70 61 79 54 65 73 74 2f 53 44 4b 2f 53 44 4b 51 75 65 72 79 2e 61 73 70 78 } //1 DemoHeepayTest/SDK/SDKQuery.aspx
		$a_01_3 = {62 61 73 65 36 34 20 2d 64 20 3e 20 2f 74 6d 70 2f 24 24 2e 62 69 6e } //1 base64 -d > /tmp/$$.bin
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}