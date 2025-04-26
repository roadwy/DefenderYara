
rule Trojan_BAT_Zilla_GPA_MTB{
	meta:
		description = "Trojan:BAT/Zilla.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {59 93 61 11 ?? 11 ?? 11 ?? 58 1f ?? 58 11 ?? 5d 93 61 d1 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}