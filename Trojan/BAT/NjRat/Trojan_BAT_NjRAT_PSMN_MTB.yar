
rule Trojan_BAT_NjRAT_PSMN_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.PSMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 28 0a 00 00 0a 28 01 00 00 2b 0a 72 2f 01 00 70 0b 16 0c 2b 2d 06 08 6f 30 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}