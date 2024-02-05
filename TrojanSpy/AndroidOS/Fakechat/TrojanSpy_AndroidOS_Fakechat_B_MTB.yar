
rule TrojanSpy_AndroidOS_Fakechat_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Fakechat.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 68 75 6c 6b 61 70 70 2f 63 68 61 74 6c 69 74 65 } //01 00 
		$a_01_1 = {6e 65 77 73 64 61 74 61 2e 61 70 6b } //01 00 
		$a_01_2 = {63 6f 6d 2e 73 79 73 74 65 6d 2e 6d 79 61 70 70 6c 69 63 61 74 69 6f 6e 2e 41 63 74 69 76 69 74 69 65 73 2e 64 63 74 65 61 74 } //01 00 
		$a_01_3 = {6e 65 77 73 64 61 74 61 2e 62 75 6e 64 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}