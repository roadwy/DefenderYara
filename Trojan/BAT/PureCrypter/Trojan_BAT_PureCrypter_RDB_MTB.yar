
rule Trojan_BAT_PureCrypter_RDB_MTB{
	meta:
		description = "Trojan:BAT/PureCrypter.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {6f 23 00 00 0a 28 24 00 00 0a 28 01 00 00 2b 28 02 00 00 2b 0b } //00 00 
	condition:
		any of ($a_*)
 
}