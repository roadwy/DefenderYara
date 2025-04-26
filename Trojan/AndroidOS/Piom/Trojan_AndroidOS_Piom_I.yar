
rule Trojan_AndroidOS_Piom_I{
	meta:
		description = "Trojan:AndroidOS/Piom.I,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 6e 74 72 79 44 75 6f 6d 69 41 70 70 46 6f 72 4c 69 6b 65 } //2 entryDuomiAppForLike
		$a_01_1 = {67 65 74 43 4d 57 61 70 43 6f 6e 6e } //2 getCMWapConn
		$a_01_2 = {4d 79 52 65 63 55 73 65 72 4e 61 6d 65 41 64 61 70 74 65 72 } //2 MyRecUserNameAdapter
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}