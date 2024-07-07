
rule TrojanDropper_BAT_VB_K{
	meta:
		description = "TrojanDropper:BAT/VB.K,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 72 79 70 74 65 72 53 74 75 62 } //10 CrypterStub
		$a_01_1 = {41 6e 74 69 5a 6f 6e 65 41 6c 61 72 6d } //2 AntiZoneAlarm
		$a_01_2 = {49 73 56 6d 57 61 72 65 } //1 IsVmWare
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=13
 
}