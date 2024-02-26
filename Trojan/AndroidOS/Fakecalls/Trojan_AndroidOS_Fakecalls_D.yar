
rule Trojan_AndroidOS_Fakecalls_D{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.D,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {6f 6e 53 65 72 76 69 63 65 43 6f 6e 6e 65 63 74 65 64 2c 20 73 68 6f 77 41 63 63 65 73 73 3a } //02 00  onServiceConnected, showAccess:
		$a_01_1 = {45 75 68 33 54 51 70 6d 4e 44 65 4f 57 5a 4d 73 49 79 39 37 } //00 00  Euh3TQpmNDeOWZMsIy97
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_Fakecalls_D_2{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.D,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 55 70 64 61 74 65 54 69 6d 65 } //01 00  CallUpdateTime
		$a_01_1 = {42 6c 61 63 6b 4c 69 73 74 } //01 00  BlackList
		$a_01_2 = {73 65 74 52 65 63 65 69 76 65 42 6c 6f 63 6b } //01 00  setReceiveBlock
		$a_01_3 = {4e 75 6d 62 65 72 4c 69 73 74 } //00 00  NumberList
	condition:
		any of ($a_*)
 
}