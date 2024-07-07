
rule Trojan_AndroidOS_Goatrat_P{
	meta:
		description = "Trojan:AndroidOS/Goatrat.P,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 65 73 74 72 6f 79 56 69 61 48 74 74 70 } //1 destroyViaHttp
		$a_01_1 = {57 35 72 57 7a 44 78 71 } //1 W5rWzDxq
		$a_01_2 = {57 65 62 52 54 43 20 69 73 20 75 70 21 } //1 WebRTC is up!
		$a_01_3 = {67 65 74 45 72 72 6f 72 52 65 61 73 6f 6e 61 61 61 } //1 getErrorReasonaaa
		$a_01_4 = {53 65 74 20 55 73 65 72 6e 61 6d 65 20 28 75 73 65 72 6e 61 6d 65 56 61 72 69 61 76 65 6c 29 } //1 Set Username (usernameVariavel)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}