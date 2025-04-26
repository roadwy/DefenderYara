
rule Trojan_AndroidOS_Autopay_HT{
	meta:
		description = "Trojan:AndroidOS/Autopay.HT,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {7a 79 66 47 47 7a 71 54 51 56 56 52 4d 4d } //1 zyfGGzqTQVVRMM
		$a_01_1 = {79 44 6c 6b 69 51 73 6d 49 43 46 54 6d 45 78 4f 35 34 6e 4b 33 } //1 yDlkiQsmICFTmExO54nK3
		$a_01_2 = {6d 79 73 71 6c 5f 70 61 73 73 77 6f 72 64 } //1 mysql_password
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}