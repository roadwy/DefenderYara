
rule Trojan_BAT_Zilla_GPP_MTB{
	meta:
		description = "Trojan:BAT/Zilla.GPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 07 91 13 06 11 06 09 11 04 6f ?? 00 00 0a 28 ?? 00 00 0a 61 b4 28 ?? 00 00 0a 13 05 06 11 05 6f ?? 00 00 0a 11 04 17 d6 09 6f ?? 00 00 0a 5d 13 04 11 07 17 d6 13 07 11 07 11 08 8e b7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}