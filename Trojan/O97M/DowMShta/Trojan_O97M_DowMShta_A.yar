
rule Trojan_O97M_DowMShta_A{
	meta:
		description = "Trojan:O97M/DowMShta.A,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 20 2f 63 20 6d 5e 73 68 5e 74 5e 61 20 68 5e 74 74 5e 70 5e 3a 2f 5e 2f } //cmd /c m^sh^t^a h^tt^p^:/^/  10
		$a_80_1 = {63 6d 64 20 2f 63 20 6d 73 5e 68 5e 74 61 20 68 74 5e 74 70 3a 2f 5e 2f } //cmd /c ms^h^ta ht^tp:/^/  10
		$a_80_2 = {73 74 61 72 74 20 6d 73 5e 68 5e 74 61 20 68 74 5e 74 70 3a 2f 5e 2f } //start ms^h^ta ht^tp:/^/  10
		$a_80_3 = {6d 73 68 74 61 20 68 74 74 70 3a 2f 2f 30 78 62 39 30 37 64 36 30 37 2f } //mshta http://0xb907d607/  10
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*10) >=10
 
}