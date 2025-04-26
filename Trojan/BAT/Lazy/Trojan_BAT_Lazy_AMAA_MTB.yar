
rule Trojan_BAT_Lazy_AMAA_MTB{
	meta:
		description = "Trojan:BAT/Lazy.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 02 07 91 66 d2 9c 02 07 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 58 d2 81 ?? 00 00 01 02 07 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 59 d2 81 ?? 00 00 01 00 07 17 58 0b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Lazy_AMAA_MTB_2{
	meta:
		description = "Trojan:BAT/Lazy.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 20 ?? ?? ?? ?? 28 ?? 00 00 06 28 ?? 00 00 0a 20 ?? ?? ?? ?? 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 13 05 14 0a 2b 0c 00 28 ?? 00 00 06 0a de 03 26 de 00 06 2c f1 73 ?? 00 00 0a 0b 06 73 ?? 00 00 0a 0d 09 11 05 16 73 ?? 00 00 0a 13 04 11 04 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 28 ?? 00 00 06 de 1d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}