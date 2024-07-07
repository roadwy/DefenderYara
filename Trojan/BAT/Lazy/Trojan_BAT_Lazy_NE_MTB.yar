
rule Trojan_BAT_Lazy_NE_MTB{
	meta:
		description = "Trojan:BAT/Lazy.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58 90 01 04 09 8e 69 32 e8 28 05 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}