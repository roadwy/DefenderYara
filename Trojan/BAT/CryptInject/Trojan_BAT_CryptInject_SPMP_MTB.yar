
rule Trojan_BAT_CryptInject_SPMP_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.SPMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {06 18 d8 0a 06 1f 18 fe 02 0c 08 2c 03 1f 18 0a 06 1f 18 5d 16 fe 03 0d 09 2d e5 } //00 00 
	condition:
		any of ($a_*)
 
}