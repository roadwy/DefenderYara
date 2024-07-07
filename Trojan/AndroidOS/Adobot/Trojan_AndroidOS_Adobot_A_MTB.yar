
rule Trojan_AndroidOS_Adobot_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Adobot.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {47 65 74 43 6f 6e 74 61 63 74 73 54 61 73 6b } //2 GetContactsTask
		$a_00_1 = {52 75 6e 6e 69 6e 67 20 47 65 74 53 6d 73 54 61 73 6b } //1 Running GetSmsTask
		$a_00_2 = {4f 70 65 6e 20 61 64 6f 62 6f 74 } //1 Open adobot
		$a_00_3 = {61 70 70 6d 65 73 73 61 67 65 73 2e 68 65 72 6f 6b 75 61 70 70 2e 63 6f 6d } //1 appmessages.herokuapp.com
		$a_00_4 = {63 6f 6e 74 65 6e 74 3a 2f 2f 63 61 6c 6c 5f 6c 6f 67 2f 63 61 6c 6c 73 } //1 content://call_log/calls
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=6
 
}