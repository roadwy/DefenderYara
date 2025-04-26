
rule Trojan_AndroidOS_Arsink_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Arsink.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {72 65 6d 6f 76 65 2f 63 6c 6f 74 68 65 73 2f 63 6f 6d } //1 remove/clothes/com
		$a_00_1 = {67 65 74 41 6c 6c 43 61 6c 6c 73 48 69 73 74 6f 74 79 } //1 getAllCallsHistoty
		$a_00_2 = {63 61 6c 6c 64 6d 70 70 } //1 calldmpp
		$a_00_3 = {68 61 68 61 5f 6c 6f 6c } //1 haha_lol
		$a_00_4 = {5f 69 6e 66 6f 64 65 76 69 63 65 } //1 _infodevice
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}