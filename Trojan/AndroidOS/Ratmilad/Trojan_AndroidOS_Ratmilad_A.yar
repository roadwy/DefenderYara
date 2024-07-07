
rule Trojan_AndroidOS_Ratmilad_A{
	meta:
		description = "Trojan:AndroidOS/Ratmilad.A,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 45 4e 44 5f 4c 4f 47 5f 4d 45 53 53 41 47 45 5f 54 45 58 54 } //2 SEND_LOG_MESSAGE_TEXT
		$a_01_1 = {47 52 41 4e 54 45 44 5f 50 45 52 4d 49 53 53 49 4f 4e 53 5f 4c 49 53 54 } //2 GRANTED_PERMISSIONS_LIST
		$a_01_2 = {53 45 4e 44 5f 53 45 4c 46 5f 44 45 46 45 4e 43 45 5f 44 41 54 41 } //2 SEND_SELF_DEFENCE_DATA
		$a_01_3 = {72 65 63 75 72 73 69 76 65 44 6f 77 6e 6c 6f 61 64 } //2 recursiveDownload
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}