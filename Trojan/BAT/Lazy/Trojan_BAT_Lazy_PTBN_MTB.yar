
rule Trojan_BAT_Lazy_PTBN_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PTBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 13 00 00 0a 0d 03 28 90 01 01 00 00 0a 73 15 00 00 0a 13 04 11 04 09 07 08 6f 16 00 00 0a 16 73 17 00 00 0a 13 05 11 05 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}