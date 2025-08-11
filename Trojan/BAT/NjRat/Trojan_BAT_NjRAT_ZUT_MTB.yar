
rule Trojan_BAT_NjRAT_ZUT_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.ZUT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 72 a4 00 00 70 0b 06 8e 69 8d ?? 00 00 01 0c 16 0d 38 1a 00 00 00 08 09 06 09 91 07 09 07 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 09 17 58 0d 09 06 8e 69 32 e0 08 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}