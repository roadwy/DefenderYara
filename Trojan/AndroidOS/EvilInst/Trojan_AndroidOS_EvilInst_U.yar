
rule Trojan_AndroidOS_EvilInst_U{
	meta:
		description = "Trojan:AndroidOS/EvilInst.U,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 45 4e 44 5f 48 45 4c 4c 4f 5f 53 41 59 } //2 SEND_HELLO_SAY
		$a_01_1 = {64 65 66 61 75 6c 74 4b 57 41 70 69 54 69 6d 65 6f 75 74 } //2 defaultKWApiTimeout
		$a_01_2 = {4b 45 59 5f 53 41 56 45 5f 53 50 52 5f 44 4f 57 4e 4c 4f 41 44 5f 41 50 4b } //2 KEY_SAVE_SPR_DOWNLOAD_APK
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}