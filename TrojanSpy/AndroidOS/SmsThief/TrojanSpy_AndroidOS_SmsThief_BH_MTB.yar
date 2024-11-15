
rule TrojanSpy_AndroidOS_SmsThief_BH_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.BH!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 73 44 65 73 74 69 6e 61 74 69 6f 6e 41 6c 6c 6f 77 65 64 } //1 isDestinationAllowed
		$a_01_1 = {63 6f 6d 2f 61 73 64 66 69 6e 74 6f 61 73 64 66 2f 61 67 6f 6f 67 6c 65 70 6c 61 79 73 65 72 76 69 63 65 73 72 69 6e 72 6f 6c 65 } //1 com/asdfintoasdf/agoogleplayservicesrinrole
		$a_01_2 = {52 45 53 55 4c 54 5f 55 4e 53 55 50 50 4f 52 54 45 44 5f 41 52 54 5f 56 45 52 53 49 4f 4e } //1 RESULT_UNSUPPORTED_ART_VERSION
		$a_01_3 = {43 6f 6e 74 65 6e 74 49 6e 66 6f 43 6f 6d 70 61 74 } //1 ContentInfoCompat
		$a_01_4 = {52 45 53 55 4c 54 5f 49 4e 53 54 41 4c 4c 5f 53 4b 49 50 5f 46 49 4c 45 5f 53 55 43 43 45 53 53 } //1 RESULT_INSTALL_SKIP_FILE_SUCCESS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}