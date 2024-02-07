
rule TrojanSpy_AndroidOS_Sharkbot_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Sharkbot.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 65 63 65 69 76 65 72 53 4d 53 } //01 00  receiverSMS
		$a_00_1 = {6f 76 65 72 6c 61 79 4c 69 66 65 } //01 00  overlayLife
		$a_00_2 = {73 68 61 72 6b 65 64 } //02 00  sharked
		$a_03_3 = {3a 00 1b 00 6e 20 90 02 05 04 00 0a 02 d8 03 00 ff df 02 02 90 01 01 8e 22 50 02 01 00 3a 03 0e 00 d8 00 03 ff 6e 20 90 02 05 34 00 0a 02 df 02 02 90 01 01 8e 22 50 02 01 03 28 e6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}