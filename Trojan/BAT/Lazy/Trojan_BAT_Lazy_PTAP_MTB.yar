
rule Trojan_BAT_Lazy_PTAP_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PTAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 55 0f 00 06 17 28 56 0f 00 06 75 7a 00 00 01 28 9e 02 00 06 7e 90 00 00 04 25 3a 17 00 00 00 26 7e 8f 00 00 04 fe 06 a3 02 00 06 73 fe 00 00 0a 25 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}