
rule Trojan_BAT_Lazy_PTIV_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PTIV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 f3 03 00 70 72 17 04 00 70 73 9e 00 00 0a 6f 9f 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}