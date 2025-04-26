
rule Trojan_AndroidOS_Zitmo_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Zitmo.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 73 79 73 74 65 6d 73 65 63 75 72 69 74 79 36 2f 67 6d 73 } //10 com/systemsecurity6/gms
		$a_01_1 = {54 6f 74 61 6c 48 69 64 65 53 6d 73 } //10 TotalHideSms
		$a_01_2 = {73 6f 66 74 74 68 72 69 66 74 79 2e 63 6f 6d 2f 73 65 63 75 72 69 74 79 2e 6a 73 70 } //1 softthrifty.com/security.jsp
		$a_01_3 = {45 78 74 72 61 63 74 4e 75 6d 62 65 72 46 72 6f 6d 4d 65 73 73 61 67 65 } //1 ExtractNumberFromMessage
		$a_01_4 = {53 6d 73 42 6c 6f 63 6b 65 72 54 68 72 65 61 64 } //1 SmsBlockerThread
		$a_01_5 = {53 65 6e 64 43 6f 6e 74 72 6f 6c 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 SendControlInformation
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=12
 
}