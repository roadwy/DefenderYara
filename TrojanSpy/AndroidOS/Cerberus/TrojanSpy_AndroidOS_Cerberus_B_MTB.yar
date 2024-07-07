
rule TrojanSpy_AndroidOS_Cerberus_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Cerberus.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 68 69 6c 65 53 74 61 72 74 55 70 64 61 74 65 49 6e 65 63 74 69 6f 6e } //1 whileStartUpdateInection
		$a_01_1 = {61 63 74 69 6f 6e 3d 73 65 6e 64 4b 65 79 6c 6f 67 67 65 72 } //1 action=sendKeylogger
		$a_01_2 = {6c 6f 63 6b 44 65 76 69 63 65 } //1 lockDevice
		$a_01_3 = {6c 69 73 74 41 70 70 47 72 61 62 43 61 72 64 73 } //1 listAppGrabCards
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}