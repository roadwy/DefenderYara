
rule Trojan_AndroidOS_FakeInst_P_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.P!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {78 42 6f 74 4c 6f 63 6b 65 72 } //1 xBotLocker
		$a_01_1 = {69 73 73 6d 73 74 69 6d 65 72 } //1 issmstimer
		$a_01_2 = {63 6f 6d 2f 6d 61 6c 69 63 65 2f 75 70 64 61 74 65 72 } //1 com/malice/updater
		$a_01_3 = {78 42 6f 74 53 65 72 76 69 63 65 } //1 xBotService
		$a_01_4 = {2f 69 6e 74 65 72 66 61 63 65 2e 70 68 70 } //1 /interface.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}