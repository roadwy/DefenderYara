
rule TrojanSpy_AndroidOS_Svpeng_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Svpeng.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 61 73 6b 73 4d 79 } //01 00  TasksMy
		$a_01_1 = {73 61 76 65 5f 6d 65 73 73 61 67 65 2e 70 68 70 } //01 00  save_message.php
		$a_01_2 = {73 61 76 65 5f 62 61 6c 61 6e 63 65 } //01 00  save_balance
		$a_01_3 = {52 65 63 69 76 65 4d 73 67 } //01 00  ReciveMsg
		$a_01_4 = {67 65 74 74 61 73 6b } //01 00  gettask
		$a_01_5 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 73 65 72 76 69 63 65 63 6f 72 65 2f 75 70 64 61 74 65 61 70 70 } //00 00  Lcom/android/servicecore/updateapp
	condition:
		any of ($a_*)
 
}