
rule Trojan_AndroidOS_Subscriber_C{
	meta:
		description = "Trojan:AndroidOS/Subscriber.C,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {75 73 74 61 62 6c 65 62 65 6e 63 68 5f 70 61 } //1 ustablebench_pa
		$a_01_1 = {6f 6e 4e 6f 74 69 66 69 63 61 74 69 6f 6e 52 65 6d 6f 76 65 64 20 20 31 31 31 31 31 31 31 31 31 31 } //1 onNotificationRemoved  1111111111
		$a_01_2 = {74 61 6b 65 6f 66 66 66 6f 6f 74 5f 63 6f 72 } //1 takeofffoot_cor
		$a_01_3 = {73 68 6f 43 6f 6d 49 77 72 } //1 shoComIwr
		$a_01_4 = {74 69 6c 69 74 79 62 65 6e 63 68 5f 68 61 76 } //1 tilitybench_hav
		$a_01_5 = {74 65 72 5f 73 65 61 74 65 64 6c 65 67 63 75 } //1 ter_seatedlegcu
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}