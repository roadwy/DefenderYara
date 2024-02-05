
rule Trojan_BAT_Loki_NEA_MTB{
	meta:
		description = "Trojan:BAT/Loki.NEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 07 06 06 6f 2b 00 00 06 5b 5a 58 6f 2c 00 00 06 09 17 58 0d 09 02 } //00 00 
	condition:
		any of ($a_*)
 
}