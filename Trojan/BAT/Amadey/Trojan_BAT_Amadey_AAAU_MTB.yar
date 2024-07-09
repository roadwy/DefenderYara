
rule Trojan_BAT_Amadey_AAAU_MTB{
	meta:
		description = "Trojan:BAT/Amadey.AAAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 09 0d 11 04 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 1f 0a 0d 11 04 6f ?? 00 00 0a 13 05 1f 0b 0d 11 05 02 16 02 8e 69 6f ?? 00 00 0a 0a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}