
rule Trojan_BAT_Rozena_RDB_MTB{
	meta:
		description = "Trojan:BAT/Rozena.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {7e 09 00 00 0a 06 8e 69 6a 28 0a 00 00 0a 7e 03 00 00 04 7e 04 00 00 04 28 01 00 00 06 0b 06 16 07 06 8e 69 28 0b 00 00 0a 00 7e 09 00 00 0a 0c 7e 09 00 00 0a 7e 0c 00 00 0a 07 7e 09 00 00 0a 16 12 02 28 02 00 00 06 0d } //00 00 
	condition:
		any of ($a_*)
 
}