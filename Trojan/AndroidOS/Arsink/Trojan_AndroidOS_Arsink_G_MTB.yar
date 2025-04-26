
rule Trojan_AndroidOS_Arsink_G_MTB{
	meta:
		description = "Trojan:AndroidOS/Arsink.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 41 63 63 65 70 74 65 64 49 73 73 75 65 72 73 } //1 getAcceptedIssuers
		$a_01_1 = {63 6f 6d 2f 63 6f 75 72 73 65 2f 61 70 70 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //1 com/course/app/MainActivity
		$a_01_2 = {67 65 74 41 6c 6c 43 61 6c 6c 73 48 69 73 74 6f 74 79 } //1 getAllCallsHistoty
		$a_01_3 = {53 6b 65 74 63 68 4c 6f 67 67 65 72 } //1 SketchLogger
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}