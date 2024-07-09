
rule Backdoor_BAT_RevengeRat_KA_MTB{
	meta:
		description = "Backdoor:BAT/RevengeRat.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 07 8f ?? 00 00 01 25 71 ?? 00 00 01 11 0a 1f 1f 5f 62 d2 81 ?? 00 00 01 11 04 11 07 8f ?? 00 00 01 25 71 ?? 00 00 01 11 09 07 11 06 11 0a 58 59 1f 1f 5f 63 d2 60 d2 81 ?? 00 00 01 11 08 11 0a 58 13 08 11 08 06 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}