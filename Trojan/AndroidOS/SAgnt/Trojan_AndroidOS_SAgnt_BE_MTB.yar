
rule Trojan_AndroidOS_SAgnt_BE_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.BE!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 6d 79 2f 6e 65 77 70 72 6f 6a 65 63 74 33 39 } //1 Lcom/my/newproject39
		$a_01_1 = {54 65 6c 65 67 72 61 6d 49 6d 61 67 65 55 70 6c 6f 61 64 65 72 } //1 TelegramImageUploader
		$a_01_2 = {2f 73 65 6e 64 50 68 6f 74 6f } //1 /sendPhoto
		$a_01_3 = {73 74 61 72 74 4c 6f 67 67 69 6e 67 } //1 startLogging
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}