
rule Trojan_BAT_Lazy_PSOJ_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PSOJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 c1 05 00 06 08 8d 1a 00 00 01 13 04 7e 58 01 00 04 02 1a 58 11 04 16 08 28 90 01 03 0a 28 90 01 03 0a 11 04 16 11 04 8e 69 6f 90 01 03 0a 13 05 7e 5d 01 00 04 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}