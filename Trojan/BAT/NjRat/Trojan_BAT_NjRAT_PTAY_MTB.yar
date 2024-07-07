
rule Trojan_BAT_NjRAT_PTAY_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.PTAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 30 00 00 0a 28 90 01 01 00 00 0a 72 1b 01 00 70 28 90 01 01 00 00 0a 6f 32 00 00 0a 0a 06 6f 33 00 00 0a 0b 73 30 00 00 0a 28 90 01 01 00 00 0a 72 d6 01 00 70 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}