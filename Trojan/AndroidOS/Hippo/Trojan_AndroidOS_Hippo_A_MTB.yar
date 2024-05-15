
rule Trojan_AndroidOS_Hippo_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Hippo.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 4d 65 73 73 61 67 65 57 69 74 68 4c 6f 6f 70 65 72 } //01 00  sendMessageWithLooper
		$a_01_1 = {2f 73 64 63 61 72 64 2f 6b 75 36 2f } //01 00  /sdcard/ku6/
		$a_01_2 = {69 6e 66 6f 2e 6b 75 36 2e 63 6e 2f 63 6c 69 65 6e 74 52 65 71 75 65 73 74 } //01 00  info.ku6.cn/clientRequest
		$a_01_3 = {63 61 6e 6e 65 6c 55 70 64 61 74 65 } //00 00  cannelUpdate
	condition:
		any of ($a_*)
 
}