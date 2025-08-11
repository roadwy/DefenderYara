
rule Trojan_BAT_Genie_PGG_MTB{
	meta:
		description = "Trojan:BAT/Genie.PGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 2c 75 00 0f 01 28 ?? 00 00 0a 1f 10 62 0f 01 28 ?? 00 00 0a 1e 62 60 0f 01 28 ?? 00 00 0a 60 13 06 02 19 8d 88 00 00 01 25 16 11 06 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 06 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 06 20 ff 00 00 00 5f d2 9c 6f ?? 00 00 0a 00 06 11 06 5a 13 07 11 07 16 fe 04 13 08 11 08 2c 0c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}