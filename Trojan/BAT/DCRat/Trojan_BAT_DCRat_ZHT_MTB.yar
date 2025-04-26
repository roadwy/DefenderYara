
rule Trojan_BAT_DCRat_ZHT_MTB{
	meta:
		description = "Trojan:BAT/DCRat.ZHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 0a 16 0b 38 13 00 00 00 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 3f e4 ff ff ff } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}