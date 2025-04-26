
rule Trojan_AndroidOS_Fakecalls_D{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.D,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {75 70 64 61 74 65 5f 68 75 68 75 } //1 update_huhu
		$a_01_1 = {75 70 6c 6f 61 64 53 4d 53 46 69 6c 65 } //1 uploadSMSFile
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_AndroidOS_Fakecalls_D_2{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.D,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {6f 6e 53 65 72 76 69 63 65 43 6f 6e 6e 65 63 74 65 64 2c 20 73 68 6f 77 41 63 63 65 73 73 3a } //2 onServiceConnected, showAccess:
		$a_01_1 = {45 75 68 33 54 51 70 6d 4e 44 65 4f 57 5a 4d 73 49 79 39 37 } //2 Euh3TQpmNDeOWZMsIy97
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_AndroidOS_Fakecalls_D_3{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.D,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 55 70 64 61 74 65 54 69 6d 65 } //2 CallUpdateTime
		$a_01_1 = {42 6c 61 63 6b 4c 69 73 74 } //1 BlackList
		$a_01_2 = {73 65 74 52 65 63 65 69 76 65 42 6c 6f 63 6b } //1 setReceiveBlock
		$a_01_3 = {4e 75 6d 62 65 72 4c 69 73 74 } //1 NumberList
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}