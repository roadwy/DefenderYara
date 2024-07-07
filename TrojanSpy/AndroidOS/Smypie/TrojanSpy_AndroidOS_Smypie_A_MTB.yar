
rule TrojanSpy_AndroidOS_Smypie_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Smypie.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {54 72 79 20 74 6f 20 64 69 73 61 62 6c 65 20 76 65 72 69 66 79 20 61 70 70 73 } //1 Try to disable verify apps
		$a_01_1 = {4d 53 70 79 49 4d 45 } //1 MSpyIME
		$a_01_2 = {46 4f 52 43 45 5f 47 50 53 } //1 FORCE_GPS
		$a_00_3 = {4d 6f 6e 69 74 6f 72 20 73 74 61 72 74 65 64 } //1 Monitor started
		$a_00_4 = {52 65 6d 6f 76 65 20 68 65 6c 70 65 72 20 61 70 70 } //1 Remove helper app
		$a_00_5 = {6c 6f 63 61 74 69 6f 6e 5f 70 72 6f 76 69 64 65 72 73 5f 61 6c 6c 6f 77 65 64 } //1 location_providers_allowed
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}