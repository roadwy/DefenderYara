
rule Trojan_BAT_Heracles_ABH_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ABH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {18 13 04 11 12 20 ?? 00 00 00 94 20 ?? aa 00 00 59 13 11 38 ?? fc ff ff 12 00 28 ?? 00 00 06 11 12 20 ?? 00 00 00 94 20 ?? 49 00 00 59 13 11 38 ?? fc ff ff 06 7b ?? 00 00 04 6f ?? 00 00 0a 03 fe 04 16 fe 01 13 0e 11 0e 2c 09 1f 18 13 11 38 ?? fb ff ff 11 12 20 ?? 01 00 00 94 20 ?? 05 00 00 59 2b e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}