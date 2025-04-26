
rule Trojan_AndroidOS_GriftHorse_C{
	meta:
		description = "Trojan:AndroidOS/GriftHorse.C,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {26 73 75 62 5f 69 64 5f 38 3d 7b 63 6c 69 63 6b 4b 65 79 7d 26 } //2 &sub_id_8={clickKey}&
		$a_01_1 = {6e 62 6d 62 74 65 73 6c 65 72 62 6f 6d 6e 62 } //2 nbmbteslerbomnb
		$a_01_2 = {41 70 70 73 46 69 6e 69 74 } //2 AppsFinit
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}