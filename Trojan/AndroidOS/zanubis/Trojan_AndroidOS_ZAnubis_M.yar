
rule Trojan_AndroidOS_ZAnubis_M{
	meta:
		description = "Trojan:AndroidOS/ZAnubis.M,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 65 72 76 69 63 69 6f 2f 49 6e 74 53 72 76 52 65 71 75 65 73 74 } //2 servicio/IntSrvRequest
		$a_01_1 = {53 72 76 54 6f 61 73 74 41 63 63 65 73 69 62 69 6c 69 64 61 64 } //2 SrvToastAccesibilidad
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}