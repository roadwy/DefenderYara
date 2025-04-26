
rule TrojanSpy_AndroidOS_Zanubis_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Zanubis.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {76 61 6c 75 2f 72 61 6e 6f 2f 67 6f 7a 61 } //1 valu/rano/goza
		$a_01_1 = {63 61 6d 75 64 69 64 6f 66 69 63 61 } //1 camudidofica
		$a_01_2 = {73 69 66 65 72 69 63 6f 64 6f 6d 75 } //1 sifericodomu
		$a_01_3 = {6e 69 76 61 6c 69 7a 6f 6d 69 6e 6f } //1 nivalizomino
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}