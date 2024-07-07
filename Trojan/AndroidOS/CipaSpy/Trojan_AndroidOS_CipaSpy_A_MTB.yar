
rule Trojan_AndroidOS_CipaSpy_A_MTB{
	meta:
		description = "Trojan:AndroidOS/CipaSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {61 70 79 42 61 6e 6b 44 61 74 61 } //1 apyBankData
		$a_01_1 = {72 65 71 75 65 73 74 4d 6f 62 69 6c 65 4d 73 67 } //1 requestMobileMsg
		$a_01_2 = {67 65 74 58 66 57 69 74 68 48 6f 6c 64 69 6e 67 42 61 6e 6b 43 6f 64 65 } //1 getXfWithHoldingBankCode
		$a_01_3 = {67 65 74 41 6c 6c 42 61 6e 6b 43 6f 64 65 5f 55 52 4c } //1 getAllBankCode_URL
		$a_03_4 = {7a 69 66 75 2f 70 61 79 6d 65 6e 74 2f 90 02 15 2f 7a 69 66 75 90 00 } //5
		$a_01_5 = {73 61 76 65 4d 65 73 73 61 67 65 52 65 63 6f 72 64 } //1 saveMessageRecord
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*5+(#a_01_5  & 1)*1) >=9
 
}