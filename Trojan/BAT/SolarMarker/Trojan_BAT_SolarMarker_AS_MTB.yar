
rule Trojan_BAT_SolarMarker_AS_MTB{
	meta:
		description = "Trojan:BAT/SolarMarker.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 00 07 6f ?? 00 00 0a 00 03 7b ?? 00 00 04 8e 69 06 8e 69 58 8d ?? 00 00 01 0c 16 0d 2b 3a 00 09 03 7b ?? 00 00 04 8e 69 fe 04 16 fe 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}