
rule TrojanSpy_AndroidOS_Wroba_J_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Wroba.J!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 65 41 64 6d 69 6e 52 65 63 69 76 65 72 } //01 00  DeAdminReciver
		$a_01_1 = {63 6f 6d 2e 6b 61 6b 61 6f 74 61 6c 6b 2e 73 79 6e 73 65 72 76 69 63 65 2e 54 49 4b } //01 00  com.kakaotalk.synservice.TIK
		$a_01_2 = {6b 69 6c 6c 42 61 63 6b 67 72 6f 75 6e 64 50 72 6f 63 65 73 73 65 73 } //01 00  killBackgroundProcesses
		$a_01_3 = {63 72 65 61 74 65 46 72 6f 6d 50 64 75 } //00 00  createFromPdu
	condition:
		any of ($a_*)
 
}