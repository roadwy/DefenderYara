
rule TrojanSpy_AndroidOS_FaceStealer_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FaceStealer.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 6a 64 64 2f 6c 6f 67 69 6e 2f 43 68 65 63 6b 4c 6f 67 69 6e } //1 com/jdd/login/CheckLogin
		$a_00_1 = {6d 67 2e 73 6c 30 2e 63 6f 2f 61 70 69 2f 6f 70 65 6e 2f 63 68 65 63 6b 5f 63 6b } //1 mg.sl0.co/api/open/check_ck
		$a_00_2 = {55 70 6c 6f 61 64 43 6f 6f 6b 69 65 } //1 UploadCookie
		$a_00_3 = {47 65 74 49 70 41 64 64 72 65 73 73 } //1 GetIpAddress
		$a_00_4 = {6a 75 64 67 65 49 73 4c 6f 67 69 6e 43 6f 6f 6b 69 65 } //1 judgeIsLoginCookie
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}