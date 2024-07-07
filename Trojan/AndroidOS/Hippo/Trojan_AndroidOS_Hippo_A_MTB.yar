
rule Trojan_AndroidOS_Hippo_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Hippo.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 4d 65 73 73 61 67 65 57 69 74 68 4c 6f 6f 70 65 72 } //1 sendMessageWithLooper
		$a_01_1 = {2f 73 64 63 61 72 64 2f 6b 75 36 2f } //1 /sdcard/ku6/
		$a_01_2 = {69 6e 66 6f 2e 6b 75 36 2e 63 6e 2f 63 6c 69 65 6e 74 52 65 71 75 65 73 74 } //1 info.ku6.cn/clientRequest
		$a_01_3 = {63 61 6e 6e 65 6c 55 70 64 61 74 65 } //1 cannelUpdate
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}