
rule Trojan_BAT_Nanocore_AAIK_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.AAIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 8e 69 8d ?? 00 00 01 0d 16 13 04 38 ?? 00 00 00 09 11 04 07 11 04 91 06 11 04 06 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 da } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}