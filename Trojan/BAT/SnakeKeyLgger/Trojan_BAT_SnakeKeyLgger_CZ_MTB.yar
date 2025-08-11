
rule Trojan_BAT_SnakeKeyLgger_CZ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLgger.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 19 8d 01 00 00 01 25 16 12 07 20 d4 02 00 00 20 cf 02 00 00 28 91 00 00 06 9c 25 17 12 07 20 4f 01 00 00 20 53 01 00 00 28 91 00 00 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}