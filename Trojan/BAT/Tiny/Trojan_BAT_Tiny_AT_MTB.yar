
rule Trojan_BAT_Tiny_AT_MTB{
	meta:
		description = "Trojan:BAT/Tiny.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 11 06 6f 06 00 00 0a 17 6f 08 00 00 0a 11 06 6f 06 00 00 0a 16 6f 09 00 00 0a 11 06 6f 06 00 00 0a 17 6f 0a 00 00 0a 11 06 6f 06 00 00 0a 17 6f 0b 00 00 0a 11 06 6f 06 00 00 0a 17 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}