
rule TrojanSpy_AndroidOS_Banker_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {2f 78 68 65 6c 70 65 72 64 61 74 61 2e 6a 61 72 } //2 /xhelperdata.jar
		$a_00_1 = {2f 78 68 65 6c 70 65 72 64 61 74 61 2e 64 65 78 } //1 /xhelperdata.dex
		$a_00_2 = {53 4f 5f 30 30 31 } //1 SO_001
		$a_00_3 = {63 6f 6d 2e 6d 75 66 63 2e } //1 com.mufc.
		$a_00_4 = {6c 70 2e 63 6f 6f 6b 74 72 61 63 6b 69 6e 67 2e 63 6f 6d 2f 76 31 2f 6c 73 2f 67 65 74 } //1 lp.cooktracking.com/v1/ls/get
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}