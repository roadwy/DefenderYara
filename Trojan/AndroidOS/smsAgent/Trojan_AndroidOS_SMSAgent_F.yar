
rule Trojan_AndroidOS_SMSAgent_F{
	meta:
		description = "Trojan:AndroidOS/SMSAgent.F,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 65 74 49 73 48 35 57 78 50 61 79 69 6e 67 } //1 setIsH5WxPaying
		$a_00_1 = {32 20 73 65 6e 64 53 75 63 42 79 4d 73 67 20 2d 2d 2d 2d 2d 2d 2d 2d 2d 20 70 68 6f 6e 65 20 3d 20 } //1 2 sendSucByMsg --------- phone = 
		$a_00_2 = {53 54 52 49 4e 53 4d 53 53 45 4e 44 41 43 54 49 4f 4e 20 26 20 69 73 53 4d 53 53 65 6e 64 53 75 63 63 65 65 64 20 3d 20 } //1 STRINSMSSENDACTION & isSMSSendSucceed = 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}