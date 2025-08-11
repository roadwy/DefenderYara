
rule Trojan_BAT_CrimsonRat_AMS_MTB{
	meta:
		description = "Trojan:BAT/CrimsonRat.AMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 00 06 0d 16 13 04 2b 37 09 11 04 9a 0b 00 07 6f ?? 00 00 0a 2c 0e 07 6f ?? 00 00 0a 18 fe 01 16 fe 01 2b 01 17 0c 08 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}