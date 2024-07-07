
rule Trojan_BAT_Lazy_PSTY_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PSTY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 73 18 00 00 0a 13 04 11 04 72 eb 02 00 70 72 9e 03 00 70 6f 90 01 01 00 00 0a 00 72 9e 03 00 70 28 90 01 01 00 00 0a 26 02 28 90 01 01 00 00 06 00 00 15 28 90 01 01 00 00 0a 00 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}