
rule TrojanSpy_AndroidOS_SpyAgent_J{
	meta:
		description = "TrojanSpy:AndroidOS/SpyAgent.J,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {56 6f 43 6f 6e 74 5f 61 63 74 50 68 5f 6f 6e 65 55 74 69 6c } //1 VoCont_actPh_oneUtil
		$a_01_1 = {56 6f 53 65 6e 5f 73 6f 72 55 74 69 6c } //1 VoSen_sorUtil
		$a_01_2 = {56 6f 42 61 74 5f 74 65 72 79 55 74 69 6c } //1 VoBat_teryUtil
		$a_01_3 = {56 6f 43 6f 5f 6e 74 61 63 74 45 6d 5f 61 69 6c 55 74 69 6c } //1 VoCo_ntactEm_ailUtil
		$a_01_4 = {56 6f 53 74 6f 72 5f 61 67 65 55 74 69 6c } //1 VoStor_ageUtil
		$a_01_5 = {56 6f 43 6f 6e 74 5f 61 63 74 41 64 5f 64 72 65 73 73 55 74 69 6c } //1 VoCont_actAd_dressUtil
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}