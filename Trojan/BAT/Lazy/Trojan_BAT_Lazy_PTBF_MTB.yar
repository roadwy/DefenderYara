
rule Trojan_BAT_Lazy_PTBF_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PTBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 14 0a 02 28 ?? 00 00 06 0a 02 03 04 28 ?? 00 00 06 0a 06 28 ?? 00 00 0a 00 06 0b 2b 00 07 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}