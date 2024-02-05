
rule Trojan_BAT_Bandra_ABW_MTB{
	meta:
		description = "Trojan:BAT/Bandra.ABW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {73 24 00 00 06 0a 06 28 90 01 03 0a 7d 30 00 00 04 06 02 7d 31 00 00 04 06 03 7d 32 00 00 04 06 15 7d 2f 00 00 04 06 7c 30 00 00 04 12 00 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}