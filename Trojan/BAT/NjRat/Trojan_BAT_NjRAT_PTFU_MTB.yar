
rule Trojan_BAT_NjRAT_PTFU_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.PTFU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 02 08 17 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 07 da 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 00 08 17 d6 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}