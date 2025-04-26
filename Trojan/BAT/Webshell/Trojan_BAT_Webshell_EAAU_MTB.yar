
rule Trojan_BAT_Webshell_EAAU_MTB{
	meta:
		description = "Trojan:BAT/Webshell.EAAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 0b 11 0c 11 0d 6f 92 00 00 0a 6f 23 00 00 0a 72 19 16 00 70 28 24 00 00 0a 6f 93 00 00 0a 26 00 11 0d 17 58 13 0d 11 0d 11 0c 6f 94 00 00 0a fe 04 13 10 11 10 2d c7 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}