
rule Trojan_BAT_Crysan_ACN_MTB{
	meta:
		description = "Trojan:BAT/Crysan.ACN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 0b 00 00 0a 0a 02 73 0c 00 00 0a 0b 00 06 07 6f 90 01 03 0a 74 01 00 00 1b 0c de 10 07 14 fe 01 0d 09 2d 07 07 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}