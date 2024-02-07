
rule Trojan_AndroidOS_Boogr_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Boogr.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 06 00 00 02 00 "
		
	strings :
		$a_00_0 = {73 70 79 2e 63 61 73 68 6e 6f 77 2e 65 65 2f 61 70 69 2f 64 65 76 69 63 65 4d 65 73 73 61 67 65 73 } //01 00  spy.cashnow.ee/api/deviceMessages
		$a_00_1 = {63 6f 6e 74 61 63 74 73 5f 63 61 6c 6c 73 } //01 00  contacts_calls
		$a_00_2 = {67 65 74 61 6e 64 53 61 76 65 49 6d 65 69 } //01 00  getandSaveImei
		$a_00_3 = {57 68 61 74 73 41 70 70 2f 4d 65 64 69 61 2f 57 68 61 74 73 41 70 70 20 49 6d 61 67 65 73 } //01 00  WhatsApp/Media/WhatsApp Images
		$a_00_4 = {54 65 6c 65 67 72 61 6d 2f 54 65 6c 65 67 72 61 6d 20 49 6d 61 67 65 73 } //01 00  Telegram/Telegram Images
		$a_00_5 = {73 70 79 64 62 } //00 00  spydb
	condition:
		any of ($a_*)
 
}