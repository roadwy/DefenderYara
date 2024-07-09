
rule TrojanSpy_AndroidOS_Cambot_A{
	meta:
		description = "TrojanSpy:AndroidOS/Cambot.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {3a 00 1c 00 6e 20 ?? ?? 14 00 0a 00 d8 03 01 ff df 00 00 0d 8e 00 50 00 02 01 3a 03 0f 00 d8 00 03 ff 6e 20 ?? ?? 34 00 0a 01 df 01 01 66 8e 11 50 01 02 03 01 01 28 e5 } //2
		$a_00_1 = {2f 70 72 69 76 61 74 65 2f 61 64 64 5f 6c 6f 67 2e 70 68 70 } //1 /private/add_log.php
		$a_00_2 = {2f 72 65 73 69 76 65 72 62 6f 6f 74 } //1 /resiverboot
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}