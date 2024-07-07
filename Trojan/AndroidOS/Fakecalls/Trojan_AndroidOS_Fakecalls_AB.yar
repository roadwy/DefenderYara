
rule Trojan_AndroidOS_Fakecalls_AB{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.AB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 41 4c 4c 4c 4f 47 55 50 4c 4f 41 44 5f 55 52 4c } //2 CALLLOGUPLOAD_URL
		$a_01_1 = {42 41 4e 4b 5f 55 52 4c } //2 BANK_URL
		$a_01_2 = {41 43 54 49 4f 4e 5f 53 45 4e 44 5f 44 41 54 41 } //2 ACTION_SEND_DATA
		$a_00_3 = {3f 74 79 70 65 3d 63 6f 6d 65 4f 6e 43 61 6c 6c } //2 ?type=comeOnCall
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}