
rule Trojan_BAT_Injuke_KAAE_MTB{
	meta:
		description = "Trojan:BAT/Injuke.KAAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 05 6f ?? 00 00 0a 07 33 1e 09 17 58 0d 09 08 17 58 33 0e 06 11 04 11 05 11 04 59 6f ?? 00 00 0a 2a 11 05 17 58 13 04 11 05 17 58 13 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}