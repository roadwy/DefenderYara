
rule Trojan_BAT_Formbook_SPSG_MTB{
	meta:
		description = "Trojan:BAT/Formbook.SPSG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 18 fe 04 16 fe 01 0b 07 2c 0e 02 0f 01 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 04 19 fe 01 0c 08 2c 0e 02 0f 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}