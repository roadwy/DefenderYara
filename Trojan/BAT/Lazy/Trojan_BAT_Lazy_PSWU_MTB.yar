
rule Trojan_BAT_Lazy_PSWU_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PSWU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {12 02 28 07 00 00 06 26 7e 10 00 00 0a 0d 12 03 08 16 28 ?? 00 00 06 26 28 ?? 00 00 0a 6f ?? 00 00 0a 13 04 72 9e 01 00 70 11 04 72 cc 01 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 06 26 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}