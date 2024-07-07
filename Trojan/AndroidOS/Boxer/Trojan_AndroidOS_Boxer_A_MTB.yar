
rule Trojan_AndroidOS_Boxer_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Boxer.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4b 45 59 5f 4d 45 53 53 41 47 45 5f 44 41 54 41 5f 54 45 58 54 } //1 KEY_MESSAGE_DATA_TEXT
		$a_01_1 = {67 65 74 50 72 65 66 69 78 41 6e 64 4e 75 6d 62 65 72 } //1 getPrefixAndNumber
		$a_01_2 = {63 6e 74 72 79 54 61 67 } //1 cntryTag
		$a_01_3 = {4b 45 59 5f 53 55 42 49 44 5f 52 45 43 45 49 56 45 44 } //1 KEY_SUBID_RECEIVED
		$a_01_4 = {62 65 67 69 6e 53 65 6e 64 69 6e 67 } //1 beginSending
		$a_01_5 = {67 65 74 4d 6d 69 52 75 6e 6e 69 6e 67 54 65 78 74 } //1 getMmiRunningText
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}