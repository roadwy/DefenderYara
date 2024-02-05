
rule Trojan_BAT_CryptInject_MBCU_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBCU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {07 09 07 09 91 03 11 04 91 61 d2 9c 11 04 17 58 13 04 11 04 03 8e 69 32 e7 } //00 00 
	condition:
		any of ($a_*)
 
}