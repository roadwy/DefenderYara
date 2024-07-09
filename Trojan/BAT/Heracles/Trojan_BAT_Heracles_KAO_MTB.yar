
rule Trojan_BAT_Heracles_KAO_MTB{
	meta:
		description = "Trojan:BAT/Heracles.KAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 17 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 03 04 6f ?? 00 00 0a 0b 07 02 16 02 8e 69 6f ?? 00 00 0a 0c 07 6f ?? 00 00 0a 06 6f ?? 00 00 0a 08 2a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}