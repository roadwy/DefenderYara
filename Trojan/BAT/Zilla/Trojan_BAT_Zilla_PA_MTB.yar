
rule Trojan_BAT_Zilla_PA_MTB{
	meta:
		description = "Trojan:BAT/Zilla.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 91 61 d2 81 ?? ?? 00 01 11 ?? 17 58 13 ?? 11 ?? 11 06 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}