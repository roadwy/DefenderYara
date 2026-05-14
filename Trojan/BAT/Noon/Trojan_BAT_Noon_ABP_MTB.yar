
rule Trojan_BAT_Noon_ABP_MTB{
	meta:
		description = "Trojan:BAT/Noon.ABP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 18 91 13 0a 38 ?? fe ff ff 11 02 75 ?? 00 00 02 14 fe 03 13 2a 38 ?? fd ff ff 38 ?? 04 00 00 38 ?? 01 00 00 02 11 03 11 04 6f ?? 00 00 0a 13 07 38 ?? 02 00 00 11 06 03 fe 04 16 fe 01 13 13 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}