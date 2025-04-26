
rule TrojanSpy_AndroidOS_Boogr_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Boogr.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_00_0 = {63 61 72 63 61 2e 73 68 69 70 72 69 73 74 2e 61 70 70 } //5 carca.shiprist.app
		$a_00_1 = {63 68 65 6e 6e 61 2e 63 6f 2e 69 6e } //5 chenna.co.in
		$a_00_2 = {63 61 6c 6c 5f 6c 6f 67 2f 63 61 6c 6c 73 } //1 call_log/calls
		$a_00_3 = {63 6f 6e 74 61 63 74 73 6c 69 73 74 } //1 contactslist
		$a_00_4 = {63 61 6e 47 65 74 4c 6f 63 61 74 69 6f 6e } //1 canGetLocation
		$a_00_5 = {73 49 4d 49 6e 66 6f } //1 sIMInfo
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=12
 
}