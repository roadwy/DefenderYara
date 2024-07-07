
rule TrojanSpy_AndroidOS_FakeInst_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeInst.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 74 65 61 6c 65 64 5f 73 6d 73 } //1 stealed_sms
		$a_00_1 = {52 65 69 63 68 5f 53 4d 53 47 61 74 65 } //1 Reich_SMSGate
		$a_00_2 = {6c 6f 61 64 53 70 61 6d } //1 loadSpam
		$a_00_3 = {73 70 61 6d 6c 69 73 74 2e 74 78 74 } //1 spamlist.txt
		$a_00_4 = {2f 66 6c 61 73 68 70 6c 61 79 65 72 5f 2f 46 55 3b } //1 /flashplayer_/FU;
		$a_01_5 = {46 4c 41 53 48 5f 50 4c 55 47 49 4e 5f 49 4e 53 54 41 4c 4c 41 54 49 4f 4e } //1 FLASH_PLUGIN_INSTALLATION
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}