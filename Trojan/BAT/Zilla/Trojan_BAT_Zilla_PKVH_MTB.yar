
rule Trojan_BAT_Zilla_PKVH_MTB{
	meta:
		description = "Trojan:BAT/Zilla.PKVH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 09 11 07 11 09 3b aa 00 00 00 11 07 6f ?? 00 00 06 13 05 12 05 28 ?? 00 00 0a 11 09 6f ?? 00 00 06 13 05 12 05 28 ?? 00 00 0a 59 11 07 6f ?? 00 00 06 13 05 12 05 28 ?? 00 00 0a 11 09 6f ?? 00 00 06 13 05 12 05 28 ?? 00 00 0a 59 13 0a 25 5a 11 0a 11 0a 5a 58 6c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}