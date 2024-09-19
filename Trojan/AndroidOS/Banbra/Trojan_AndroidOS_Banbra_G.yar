
rule Trojan_AndroidOS_Banbra_G{
	meta:
		description = "Trojan:AndroidOS/Banbra.G,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 72 6c 53 74 72 69 6e 67 41 70 69 54 65 6c 65 67 72 61 6d } //2 urlStringApiTelegram
		$a_01_1 = {74 65 78 4d 6f 64 69 66 69 63 61 64 6f 78 } //2 texModificadox
		$a_01_2 = {53 65 72 76 69 63 65 61 4c 52 4d 41 } //2 ServiceaLRMA
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}