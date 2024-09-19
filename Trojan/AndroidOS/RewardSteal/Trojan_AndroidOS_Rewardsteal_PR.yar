
rule Trojan_AndroidOS_Rewardsteal_PR{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.PR,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 65 74 61 2d 63 61 72 6f 74 65 6e 65 2e 30 30 30 77 65 62 68 6f 73 74 61 70 70 2e 63 6f 6d 2f } //1 beta-carotene.000webhostapp.com/
		$a_01_1 = {63 6f 6d 2e 65 78 61 2e 68 68 6b 68 6b 68 6b 68 6b 2e 6a 68 6b 68 6b 68 6b 68 6b 2e 6a 68 6b 68 6b 68 6b 68 6b 68 6b 2e 6d 70 6c 65 2e 74 65 73 74 74 74 74 74 74 } //1 com.exa.hhkhkhkhk.jhkhkhkhk.jhkhkhkhkhk.mple.testttttt
		$a_01_2 = {6d 57 65 62 77 21 21 2e 67 65 74 53 65 74 74 69 6e 67 73 28 29 } //1 mWebw!!.getSettings()
		$a_01_3 = {53 31 6d 32 73 33 52 34 65 35 63 36 6a 6b 73 64 66 68 6b 73 64 68 6b 66 68 6b 73 68 66 65 37 69 38 76 39 65 30 72 } //1 S1m2s3R4e5c6jksdfhksdhkfhkshfe7i8v9e0r
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}