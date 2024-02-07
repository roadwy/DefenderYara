
rule Trojan_AndroidOS_Telerat_C{
	meta:
		description = "Trojan:AndroidOS/Telerat.C,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {62 34 61 2e 65 78 61 6d 70 6c 65 2e 62 6f 74 72 61 74 } //01 00  b4a.example.botrat
		$a_00_1 = {5f 61 5f 70 69 63 74 75 72 65 74 61 6b 65 6e } //01 00  _a_picturetaken
		$a_00_2 = {5f 73 6d 73 69 6e 73 5f 6d 65 73 73 61 67 65 73 65 6e 74 } //00 00  _smsins_messagesent
	condition:
		any of ($a_*)
 
}