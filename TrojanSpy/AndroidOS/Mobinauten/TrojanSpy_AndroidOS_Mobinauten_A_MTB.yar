
rule TrojanSpy_AndroidOS_Mobinauten_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Mobinauten.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {64 65 2e 6d 6f 62 69 6e 61 75 74 65 6e 2e 73 6d 73 73 70 79 } //1 de.mobinauten.smsspy
		$a_01_1 = {53 4d 53 53 50 59 } //1 SMSSPY
		$a_01_2 = {4c 6f 63 61 74 69 6f 6e 20 52 65 71 75 65 73 74 20 72 65 63 65 69 76 65 64 2e 2e 2e 49 27 6d 20 77 6f 72 6b 69 6e 67 } //1 Location Request received...I'm working
		$a_00_3 = {46 6f 75 6e 64 20 69 64 20 6f 66 20 6e 61 6d 65 20 73 79 73 74 65 6d 6e 75 6d 62 65 72 20 69 6e 20 63 6f 6e 74 61 63 74 73 } //1 Found id of name systemnumber in contacts
		$a_00_4 = {53 4d 53 20 44 61 74 61 62 61 73 65 20 6f 70 74 69 6d 69 7a 65 64 } //1 SMS Database optimized
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}