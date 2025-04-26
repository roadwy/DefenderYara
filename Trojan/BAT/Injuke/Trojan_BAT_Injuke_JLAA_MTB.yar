
rule Trojan_BAT_Injuke_JLAA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.JLAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 06 07 09 9c 1d 2c 22 07 16 2d cc 17 25 2c 0e 58 0b 07 02 7b ?? 00 00 04 6f ?? 00 00 0a 16 2d ec 32 bc 02 06 7d ?? 00 00 04 02 7b ?? 00 00 04 25 2d 03 26 2b 05 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}