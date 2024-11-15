
rule Trojan_BAT_Lazy_AJS_MTB{
	meta:
		description = "Trojan:BAT/Lazy.AJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 01 72 bb 00 00 70 28 20 00 00 06 72 ed 00 00 70 28 20 00 00 06 28 21 00 00 06 13 0c 20 00 00 00 00 7e 90 00 00 04 7b 6e 00 00 04 39 0f 00 00 00 26 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}