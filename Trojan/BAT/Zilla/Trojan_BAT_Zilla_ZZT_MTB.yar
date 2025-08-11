
rule Trojan_BAT_Zilla_ZZT_MTB{
	meta:
		description = "Trojan:BAT/Zilla.ZZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {05 11 04 18 5a 6b 58 13 06 03 11 05 0f 02 28 ?? 00 00 0a 11 06 22 00 00 00 40 5b 59 0f 02 28 ?? 00 00 0a 11 06 22 00 00 00 40 5b 59 11 06 11 06 6f ?? 01 00 0a de 0c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}