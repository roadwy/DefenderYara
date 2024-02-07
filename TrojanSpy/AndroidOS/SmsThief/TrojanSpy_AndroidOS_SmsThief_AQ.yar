
rule TrojanSpy_AndroidOS_SmsThief_AQ{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AQ,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 6e 65 6f 6e 65 74 2e 61 70 70 2e 72 65 61 64 65 72 } //05 00  com.neonet.app.reader
		$a_01_1 = {4c 63 6f 6d 2f 63 61 6e 6e 61 76 2f 63 75 61 73 69 6d 6f 64 6f 2f 6a 75 6d 70 65 72 2f 73 6f 6d 61 6c 69 61 3b } //00 00  Lcom/cannav/cuasimodo/jumper/somalia;
	condition:
		any of ($a_*)
 
}