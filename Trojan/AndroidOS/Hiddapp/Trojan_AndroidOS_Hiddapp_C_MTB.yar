
rule Trojan_AndroidOS_Hiddapp_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Hiddapp.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2f 41 64 73 41 63 74 69 76 69 74 79 } //1 main/AdsActivity
		$a_01_1 = {73 65 74 41 50 4b 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 setAPKClassLoader
		$a_01_2 = {73 74 61 72 74 41 64 73 41 63 74 69 76 69 74 79 } //1 startAdsActivity
		$a_00_3 = {69 73 65 6d 75 6c 61 74 6f 72 } //1 isemulator
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}