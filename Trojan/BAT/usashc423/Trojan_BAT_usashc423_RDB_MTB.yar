
rule Trojan_BAT_usashc423_RDB_MTB{
	meta:
		description = "Trojan:BAT/usashc423.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 66 30 35 64 66 31 34 2d 63 30 64 31 2d 34 33 64 63 2d 39 63 66 39 2d 61 61 61 37 33 36 33 36 61 33 33 38 } //1 cf05df14-c0d1-43dc-9cf9-aaa73636a338
		$a_01_1 = {11 06 11 07 11 05 11 07 6f 61 00 00 0a 20 3b 0e 00 00 61 d1 9d } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}