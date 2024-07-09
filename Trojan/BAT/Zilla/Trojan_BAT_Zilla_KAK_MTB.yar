
rule Trojan_BAT_Zilla_KAK_MTB{
	meta:
		description = "Trojan:BAT/Zilla.KAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 1f 64 d6 17 d6 8d ?? 00 00 01 28 ?? 00 00 0a 74 ?? 00 00 1b 0b 08 07 11 05 1f 64 6f ?? 00 00 0a 13 06 11 06 16 2e 0e 11 05 11 06 d6 13 05 09 11 06 d6 0d 2b c4 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}