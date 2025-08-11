
rule Trojan_BAT_Lazy_SPF_MTB{
	meta:
		description = "Trojan:BAT/Lazy.SPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 d1 13 0f 11 20 11 09 91 13 28 11 20 11 09 11 26 11 28 61 11 1e 19 58 61 11 2e 61 d2 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}