
rule Trojan_BAT_AveMaria_NEDW_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEDW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 13 00 00 0a 72 67 00 00 70 28 0b 00 00 06 6f 14 00 00 0a 28 15 00 00 0a 28 02 00 00 2b 28 03 00 00 2b 0b dd 1d 00 00 00 } //10
		$a_01_1 = {62 00 6c 00 6c 00 73 00 6c 00 31 00 2e 00 73 00 68 00 6f 00 70 00 } //5 bllsl1.shop
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}