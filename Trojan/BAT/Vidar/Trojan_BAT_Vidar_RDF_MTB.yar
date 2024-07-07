
rule Trojan_BAT_Vidar_RDF_MTB{
	meta:
		description = "Trojan:BAT/Vidar.RDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {32 39 63 61 32 38 62 30 2d 36 66 33 30 2d 34 32 61 34 2d 39 37 64 35 2d 34 66 36 35 65 32 37 32 35 34 37 31 } //1 29ca28b0-6f30-42a4-97d5-4f65e2725471
		$a_01_1 = {77 65 4d 55 } //1 weMU
		$a_01_2 = {fe 0c 01 00 fe 0c 00 00 fe 0c 01 00 fe 0c 00 00 93 fe 09 02 00 61 d1 9d } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}