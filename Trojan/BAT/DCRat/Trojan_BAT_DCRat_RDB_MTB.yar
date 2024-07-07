
rule Trojan_BAT_DCRat_RDB_MTB{
	meta:
		description = "Trojan:BAT/DCRat.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 43 52 61 74 4c 6f 61 64 65 72 } //1 DCRatLoader
		$a_01_1 = {09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58 13 06 11 06 09 8e 69 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}