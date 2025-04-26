
rule Trojan_BAT_SnakeKeylogger_SPSG_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPSG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 0d 07 11 0d 91 11 04 11 04 11 07 95 11 04 11 05 95 58 20 ff 00 00 00 5f 95 61 d2 9c 11 0d 17 58 13 0d 11 0d 09 8e 69 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}