
rule Trojan_AndroidOS_MazarBot_A{
	meta:
		description = "Trojan:AndroidOS/MazarBot.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 72 65 41 6c 6c 56 62 76 46 69 65 6c 64 73 56 61 6c 69 64 } //2 areAllVbvFieldsValid
		$a_01_1 = {72 65 61 64 4d 65 73 73 61 67 65 73 46 72 6f 6d 44 65 76 69 63 65 44 42 } //2 readMessagesFromDeviceDB
		$a_01_2 = {6d 61 6b 65 49 64 53 61 76 65 64 43 6f 6e 66 69 72 6d } //2 makeIdSavedConfirm
		$a_01_3 = {42 49 4e 53 5f 57 49 54 48 4f 55 54 5f 56 42 56 } //2 BINS_WITHOUT_VBV
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=6
 
}