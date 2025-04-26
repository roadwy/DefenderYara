
rule Trojan_BAT_PureCrypter_PLLWH_MTB{
	meta:
		description = "Trojan:BAT/PureCrypter.PLLWH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 09 09 11 09 91 03 11 09 07 5d 91 61 d2 9c 11 09 17 58 13 09 11 09 08 32 e4 } //6
		$a_01_1 = {09 11 04 25 17 58 13 04 02 11 08 91 9c 11 08 04 17 58 58 13 08 11 08 06 32 e6 } //5
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*5) >=11
 
}