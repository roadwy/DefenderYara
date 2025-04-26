
rule TrojanSpy_AndroidOS_Wroba_G_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Wroba.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {4c 33 4e 68 64 6d 56 6b 61 57 35 7a 64 47 46 75 59 32 56 7a 64 47 46 30 5a 53 35 73 62 32 5a 30 5a 58 49 75 59 32 39 74 } //1 L3NhdmVkaW5zdGFuY2VzdGF0ZS5sb2Z0ZXIuY29t
		$a_00_1 = {50 68 6f 6e 65 4d 61 6e 61 67 65 72 2f 73 65 72 76 69 63 65 73 2f 42 61 6e 6b 57 65 62 53 65 72 76 69 63 65 3f 77 73 64 6c } //1 PhoneManager/services/BankWebService?wsdl
		$a_00_2 = {63 6f 6d 2f 63 61 73 68 77 65 62 2f 61 6e 64 72 6f 69 64 2f 77 6f 6f 72 69 62 61 6e 6b } //1 com/cashweb/android/wooribank
		$a_00_3 = {69 6e 69 74 57 65 62 53 65 72 76 69 63 65 55 72 6c } //1 initWebServiceUrl
		$a_00_4 = {67 65 74 4e 65 77 65 73 74 48 6f 73 74 } //1 getNewestHost
		$a_00_5 = {64 6f 77 6e 6c 6f 61 64 5f 61 6e 79 } //1 download_any
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}