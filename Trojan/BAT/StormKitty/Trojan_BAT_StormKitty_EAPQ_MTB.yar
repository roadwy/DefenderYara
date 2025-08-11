
rule Trojan_BAT_StormKitty_EAPQ_MTB{
	meta:
		description = "Trojan:BAT/StormKitty.EAPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 04 06 11 04 8f 12 00 00 01 72 37 49 00 70 28 61 01 00 0a a2 11 04 17 58 13 04 11 04 6a 07 6e 32 dd } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}