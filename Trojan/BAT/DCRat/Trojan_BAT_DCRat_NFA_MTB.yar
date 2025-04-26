
rule Trojan_BAT_DCRat_NFA_MTB{
	meta:
		description = "Trojan:BAT/DCRat.NFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 0c 17 58 93 11 05 61 13 06 17 13 0e 38 0c ff ff ff 11 0c 19 58 13 0c 11 06 1f 1f 5f } //2
		$a_01_1 = {11 0c 11 07 58 11 09 59 93 61 11 0b } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}