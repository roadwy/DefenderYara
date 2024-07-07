
rule Trojan_AndroidOS_Phonzy_A{
	meta:
		description = "Trojan:AndroidOS/Phonzy.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 70 61 6e 64 6f 72 61 2f 6f 31 34 37 2f } //2 Lcom/pandora/o147/
		$a_01_1 = {76 32 61 70 69 2e 33 78 78 2e 6c 69 76 65 } //1 v2api.3xx.live
		$a_01_2 = {44 49 53 43 4f 4e 4e 45 43 54 5f 52 45 41 53 4f 4e 5f 43 4f 44 45 5f 55 4e 4b 4e 4f 57 } //1 DISCONNECT_REASON_CODE_UNKNOW
		$a_01_3 = {55 70 6c 6f 61 64 4c 6f 6f 70 57 6f 72 6b } //1 UploadLoopWork
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}