
rule Trojan_BAT_DarkTortilla_J_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 01 a2 14 28 ?? 00 00 0a 23 00 00 00 00 00 00 1a 40 28 ?? 00 00 0a 8c ?? 00 00 01 28 ?? 00 00 0a a2 14 28 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}