
rule Trojan_BAT_Heracles_KOAA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.KOAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 04 28 ?? 00 00 0a 20 2e b8 3f 49 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 13 05 73 ?? 00 00 0a 0b 28 ?? 00 00 06 73 ?? 00 00 0a 0c 08 11 05 16 73 ?? 00 00 0a 0d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}