
rule Trojan_BAT_Lazy_PTEP_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PTEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 03 6f 20 00 00 0a 0b 04 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 26 04 07 28 90 01 01 00 00 0a de 0a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}