
rule Trojan_BAT_Lazy_RDH_MTB{
	meta:
		description = "Trojan:BAT/Lazy.RDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {26 09 11 05 16 11 05 8e 69 6f 08 00 00 0a 09 16 6a 16 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}