
rule TrojanSpy_AndroidOS_Ahmyth_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Ahmyth.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 68 6d 79 74 68 2e 6d 69 6e 65 2e 6b 69 6e 67 2e 61 68 6d 79 74 68 } //01 00  ahmyth.mine.king.ahmyth
		$a_01_1 = {63 6f 6e 74 65 6e 74 3a 2f 2f 63 61 6c 6c 5f 6c 6f 67 2f 63 61 6c 6c 73 } //01 00  content://call_log/calls
		$a_00_2 = {63 6f 6e 74 65 6e 74 3a 2f 2f 73 6d 73 2f 69 6e 62 6f 78 } //01 00  content://sms/inbox
		$a_00_3 = {78 30 30 30 30 6c 6d } //00 00  x0000lm
	condition:
		any of ($a_*)
 
}