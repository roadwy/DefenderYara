
rule TrojanSpy_AndroidOS_Vultur_JK{
	meta:
		description = "TrojanSpy:AndroidOS/Vultur.JK,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 65 63 72 79 70 74 4e 65 77 46 6f 72 6d 61 74 } //1 decryptNewFormat
		$a_01_1 = {65 6e 73 75 72 65 4f 74 70 50 61 72 61 6d 65 74 65 72 73 49 73 4d 75 74 61 62 6c 65 } //1 ensureOtpParametersIsMutable
		$a_01_2 = {63 6f 6d 2e 70 72 69 76 61 63 79 2e 61 63 63 6f 75 6e 74 2e 73 61 66 65 74 79 61 70 70 } //1 com.privacy.account.safetyapp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}