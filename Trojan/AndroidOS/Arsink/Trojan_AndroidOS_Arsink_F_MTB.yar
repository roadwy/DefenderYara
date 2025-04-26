
rule Trojan_AndroidOS_Arsink_F_MTB{
	meta:
		description = "Trojan:AndroidOS/Arsink.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 72 73 69 6e 6b 52 41 54 } //1 arsinkRAT
		$a_01_1 = {55 73 65 72 5f 41 70 70 2e 74 78 74 } //1 User_App.txt
		$a_01_2 = {61 72 73 69 6e 6b 2e 6d 70 33 } //1 arsink.mp3
		$a_01_3 = {63 61 6c 6c 64 6d 70 70 } //1 calldmpp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}