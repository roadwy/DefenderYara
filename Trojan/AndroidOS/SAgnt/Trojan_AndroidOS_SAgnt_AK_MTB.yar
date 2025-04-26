
rule Trojan_AndroidOS_SAgnt_AK_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.AK!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 6f 62 69 6c 65 49 6e 66 6f } //1 mobileInfo
		$a_01_1 = {67 65 74 42 6b 5f 74 79 70 65 } //1 getBk_type
		$a_01_2 = {69 70 2e 74 78 74 } //1 ip.txt
		$a_01_3 = {49 6e 66 6f 47 65 74 74 65 72 } //1 InfoGetter
		$a_01_4 = {49 6e 66 6f 52 65 74 75 72 6e 65 72 } //1 InfoReturner
		$a_01_5 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 6d 61 6f 6d 61 6f 2f 42 61 6e 6b 53 70 6c 61 73 68 41 63 74 69 76 69 74 79 } //10 Lcom/example/maomao/BankSplashActivity
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*10) >=14
 
}