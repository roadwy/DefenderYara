
rule Trojan_BAT_Lazy_PTDY_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PTDY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 84 02 00 70 15 16 28 ?? 00 00 0a 02 7b 11 00 00 04 28 ?? 00 00 0a 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}