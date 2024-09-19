
rule Trojan_AndroidOS_Mamont_M{
	meta:
		description = "Trojan:AndroidOS/Mamont.M,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 78 63 63 2e 56 6d 65 73 74 65 46 69 6c 6d 73 2e 65 78 74 72 61 2e 50 41 52 41 4d 31 } //2 com.xcc.VmesteFilms.extra.PARAM1
		$a_01_1 = {56 6d 65 73 74 65 46 69 6c 6d 73 2f 65 63 65 69 76 65 72 } //2 VmesteFilms/eceiver
		$a_01_2 = {63 6f 6d 2e 78 63 63 2e 56 6d 65 73 74 65 46 69 6c 6d 73 2e 61 63 74 69 6f 6e 2e 42 41 5a } //2 com.xcc.VmesteFilms.action.BAZ
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}