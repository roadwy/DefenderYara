
rule Trojan_BAT_Stealerc_GPG_MTB{
	meta:
		description = "Trojan:BAT/Stealerc.GPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 13 06 13 07 11 18 13 1c 18 8d 2c 00 00 01 13 17 11 17 16 1f 30 9e 00 11 17 17 1f f9 11 17 16 94 58 9e 00 11 1c 11 17 17 94 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}