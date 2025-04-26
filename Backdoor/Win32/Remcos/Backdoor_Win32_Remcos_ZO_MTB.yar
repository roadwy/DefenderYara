
rule Backdoor_Win32_Remcos_ZO_MTB{
	meta:
		description = "Backdoor:Win32/Remcos.ZO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 64 6b 72 69 78 65 6f 73 6b 7a 6c 72 } //1 Cdkrixeoskzlr
		$a_01_1 = {43 72 79 70 74 45 6e 63 72 79 70 74 4d 65 73 73 61 67 65 } //1 CryptEncryptMessage
		$a_01_2 = {43 72 79 70 74 4d 73 67 47 65 74 50 61 72 61 6d } //1 CryptMsgGetParam
		$a_01_3 = {57 49 4e 4e 4c 53 45 6e 61 62 6c 65 49 4d 45 } //1 WINNLSEnableIME
		$a_01_4 = {41 56 49 53 74 72 65 61 6d 54 69 6d 65 54 6f 53 61 6d 70 6c 65 } //1 AVIStreamTimeToSample
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}