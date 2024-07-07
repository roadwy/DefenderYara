
rule TrojanSpy_AndroidOS_Wroba_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Wroba.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 65 41 64 6d 69 6e 52 65 63 69 76 65 72 } //1 DeAdminReciver
		$a_01_1 = {4d 49 53 53 49 4f 4e 5f 50 4f 50 49 4e 46 4f 5f 42 59 50 41 53 53 } //1 MISSION_POPINFO_BYPASS
		$a_01_2 = {63 6f 6d 2e 78 78 78 2e 47 53 } //1 com.xxx.GS
		$a_01_3 = {6b 61 6b 61 6f 74 61 6c 6b 2e 73 79 6e 73 65 72 76 69 63 65 2e 55 52 4c } //1 kakaotalk.synservice.URL
		$a_01_4 = {63 6f 6d 2f 6c 6c 2f 46 4e 41 } //1 com/ll/FNA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}