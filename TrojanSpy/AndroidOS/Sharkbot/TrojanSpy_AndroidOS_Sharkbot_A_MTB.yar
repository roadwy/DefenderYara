
rule TrojanSpy_AndroidOS_Sharkbot_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Sharkbot.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {07 73 68 61 72 6b 65 64 00 } //01 00 
		$a_00_1 = {61 61 31 31 5f 73 74 61 72 74 5f 74 69 6d 65 } //01 00 
		$a_00_2 = {6f 76 65 72 6c 61 79 43 6c 6f 73 65 } //01 00 
		$a_00_3 = {2f 4d 79 52 65 63 65 69 76 65 72 53 4d 53 3b } //01 00 
		$a_00_4 = {2f 61 61 4f 76 65 72 6c 61 79 3b } //00 00 
		$a_00_5 = {5d 04 00 00 } //d7 cf 
	condition:
		any of ($a_*)
 
}