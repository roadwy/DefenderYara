
rule Trojan_AndroidOS_Ahmythspy_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Ahmythspy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 73 64 2e 61 70 6b } //5 asd.apk
		$a_03_1 = {2f 73 64 63 61 72 64 2f [0-12] 2e 74 78 74 } //1
		$a_01_2 = {73 74 61 72 74 41 63 74 69 76 69 74 79 46 6f 72 52 65 73 75 6c 74 } //1 startActivityForResult
		$a_01_3 = {69 6e 6a 65 63 74 65 64 4f 62 6a 65 63 74 } //1 injectedObject
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}