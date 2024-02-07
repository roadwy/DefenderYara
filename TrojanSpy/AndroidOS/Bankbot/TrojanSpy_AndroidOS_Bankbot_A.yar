
rule TrojanSpy_AndroidOS_Bankbot_A{
	meta:
		description = "TrojanSpy:AndroidOS/Bankbot.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 68 61 72 6b 65 64 2e 64 62 } //01 00  sharked.db
		$a_00_1 = {2f 61 61 42 6f 6f 74 52 65 63 65 69 76 65 72 3b } //01 00  /aaBootReceiver;
		$a_03_2 = {d8 00 00 ff 3a 00 1b 00 6e 20 90 01 01 85 04 00 0a 02 d8 03 00 ff df 02 02 90 01 01 8e 22 50 02 01 00 3a 03 0e 00 d8 00 03 ff 6e 20 90 01 01 85 34 00 0a 02 df 02 02 90 01 01 8e 22 50 02 01 03 90 00 } //01 00 
		$a_00_3 = {54 68 65 6d 65 5f 53 68 61 72 6b 65 64 31 } //00 00  Theme_Sharked1
		$a_00_4 = {5d 04 00 } //00 fb 
	condition:
		any of ($a_*)
 
}