
rule Trojan_BAT_Zilla_KA_MTB{
	meta:
		description = "Trojan:BAT/Zilla.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 06 e0 06 d2 9e 06 17 58 0a 06 20 ?? 00 00 00 36 ee } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}