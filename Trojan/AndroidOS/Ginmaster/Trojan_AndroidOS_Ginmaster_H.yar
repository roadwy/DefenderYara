
rule Trojan_AndroidOS_Ginmaster_H{
	meta:
		description = "Trojan:AndroidOS/Ginmaster.H,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 69 6e 73 74 61 6c 6c 65 72 5f 61 64 76 5f 73 75 63 63 5f 6c 6f 67 2e 70 68 70 } //1 /installer_adv_succ_log.php
		$a_01_1 = {2f 69 6e 73 74 61 6c 6c 65 72 4b 69 6e 67 2e 61 70 6b } //1 /installerKing.apk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}