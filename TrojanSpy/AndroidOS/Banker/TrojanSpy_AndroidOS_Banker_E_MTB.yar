
rule TrojanSpy_AndroidOS_Banker_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {2f 78 68 65 6c 70 65 72 64 61 74 61 2e 6a 61 72 } //01 00  /xhelperdata.jar
		$a_00_1 = {2f 78 68 65 6c 70 65 72 64 61 74 61 2e 64 65 78 } //01 00  /xhelperdata.dex
		$a_00_2 = {53 4f 5f 30 30 31 } //01 00  SO_001
		$a_00_3 = {63 6f 6d 2e 6d 75 66 63 2e } //01 00  com.mufc.
		$a_00_4 = {6c 70 2e 63 6f 6f 6b 74 72 61 63 6b 69 6e 67 2e 63 6f 6d 2f 76 31 2f 6c 73 2f 67 65 74 } //00 00  lp.cooktracking.com/v1/ls/get
	condition:
		any of ($a_*)
 
}