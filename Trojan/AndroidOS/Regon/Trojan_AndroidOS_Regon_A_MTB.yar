
rule Trojan_AndroidOS_Regon_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Regon.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {75 70 53 65 72 76 65 72 41 70 70 73 4c 69 73 74 } //1 upServerAppsList
		$a_01_1 = {75 70 53 65 72 76 65 72 43 6f 6e 74 61 63 74 4c 69 73 74 } //1 upServerContactList
		$a_01_2 = {75 70 53 65 72 76 65 72 43 61 6c 6c 4c 6f 67 73 } //1 upServerCallLogs
		$a_01_3 = {69 73 73 68 6f 77 63 61 72 64 } //1 isshowcard
		$a_01_4 = {68 6f 6f 6b 63 61 6c 6c 73 } //1 hookcalls
		$a_01_5 = {67 65 74 5f 62 72 6f 77 68 69 73 74 } //1 get_browhist
		$a_01_6 = {73 65 74 5f 69 6e 6a 65 63 74 73 } //1 set_injects
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}