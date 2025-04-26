
rule Trojan_BAT_DCRat_AAHO_MTB{
	meta:
		description = "Trojan:BAT/DCRat.AAHO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 01 00 fe 0c 02 00 fe 09 00 00 fe 0c 02 00 91 fe 0c 00 00 fe 0c 02 00 fe 0c 00 00 8e 69 5d 91 61 d2 9c fe 0c 02 00 20 01 00 00 00 58 fe 0e 02 00 fe 0c 02 00 fe 09 00 00 8e 69 3f } //4
		$a_01_1 = {32 00 47 00 4d 00 32 00 33 00 6a 00 33 00 30 00 31 00 74 00 36 00 30 00 5a 00 39 00 36 00 54 00 } //1 2GM23j301t60Z96T
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}