
rule Trojan_BAT_Webshell_SPDO_MTB{
	meta:
		description = "Trojan:BAT/Webshell.SPDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 17 8d 50 00 00 01 0d 09 16 1f 2c 9d 09 6f 90 01 03 0a 0a 16 0b 2b 25 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}