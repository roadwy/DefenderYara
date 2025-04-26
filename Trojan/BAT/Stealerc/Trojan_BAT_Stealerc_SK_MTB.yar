
rule Trojan_BAT_Stealerc_SK_MTB{
	meta:
		description = "Trojan:BAT/Stealerc.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 06 08 91 58 07 08 91 58 20 00 01 00 00 5d 0d 06 08 91 13 12 06 08 06 09 91 9c 06 09 11 12 9c 08 17 58 0c 08 20 00 01 00 00 3f d1 ff ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}