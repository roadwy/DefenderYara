
rule Trojan_BAT_Lazy_MX_MTB{
	meta:
		description = "Trojan:BAT/Lazy.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 28 31 00 00 0a 6f 32 00 00 0a 0d 06 09 6f 10 00 00 06 13 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}