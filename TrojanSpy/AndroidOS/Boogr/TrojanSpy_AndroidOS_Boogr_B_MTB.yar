
rule TrojanSpy_AndroidOS_Boogr_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Boogr.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0c 00 0c 00 06 00 00 05 00 "
		
	strings :
		$a_00_0 = {63 61 72 63 61 2e 73 68 69 70 72 69 73 74 2e 61 70 70 } //05 00  carca.shiprist.app
		$a_00_1 = {63 68 65 6e 6e 61 2e 63 6f 2e 69 6e } //01 00  chenna.co.in
		$a_00_2 = {63 61 6c 6c 5f 6c 6f 67 2f 63 61 6c 6c 73 } //01 00  call_log/calls
		$a_00_3 = {63 6f 6e 74 61 63 74 73 6c 69 73 74 } //01 00  contactslist
		$a_00_4 = {63 61 6e 47 65 74 4c 6f 63 61 74 69 6f 6e } //01 00  canGetLocation
		$a_00_5 = {73 49 4d 49 6e 66 6f } //00 00  sIMInfo
	condition:
		any of ($a_*)
 
}