
rule Trojan_AndroidOS_IOBot_A_MTB{
	meta:
		description = "Trojan:AndroidOS/IOBot.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 73 70 61 63 65 78 2e 6d 6d 6f 62 69 6c 65 } //5 com.spacex.mmobile
		$a_01_1 = {61 63 74 69 76 65 49 6e 6a 65 63 74 41 70 70 50 61 63 6b 61 67 65 } //1 activeInjectAppPackage
		$a_01_2 = {61 63 74 69 76 65 49 6e 6a 65 63 74 4c 6f 67 49 64 } //1 activeInjectLogId
		$a_01_3 = {48 49 44 44 45 4e 5f 56 4e 43 } //1 HIDDEN_VNC
		$a_01_4 = {73 70 61 63 65 78 74 72 61 66 66 69 63 2e 63 6f 6d } //1 spacextraffic.com
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}